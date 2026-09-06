package netcheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
	"github.com/Zagorsky17/ServerOk/internal/report"
)

// speedcf.go — второй способ замера скорости: против ближайшего edge-узла
// Cloudflare (тот же бэкенд, что у speed.cloudflare.com).
//
// Зачем он нужен рядом с Ookla. Ookla меряет канал до сервера конкретного
// провайдера в конкретном городе — это ответ на вопрос «как мой сервер видит
// мир». Cloudflare отвечает на другой вопрос: «какую скорость получит
// пользователь, качая с CDN», и заодно не зависит от того, жив ли сегодня
// спонсор в нужном городе. Именно на серверах, где половина строк Ookla
// падает в «Test failed», этот способ и выручает.
//
// Регион здесь не выбирается: адрес anycast, и трафик всегда идёт в
// ближайший дата-центр Cloudflare. Поэтому строка в отчёте всегда одна, а её
// имя содержит код колонии (colo), в которую попали — по нему видно, куда
// именно мерили.

const (
	cfBase = "https://speed.cloudflare.com"
	// cfStreams — сколько параллельных потоков (зачем они — см. speedwindow.go).
	// Четыре: до ближайшего edge-узла плечо короткое, а нагружать чужой сервис
	// сильнее незачем.
	cfStreams = 4
	// Длительность окна и разгон — см. measureWindow: замер идёт фиксированное
	// время, первые cfWarmup секунд не считаются.
	cfDownWindow = 5 * time.Second
	cfUpWindow   = 5 * time.Second
	cfWarmup     = 1500 * time.Millisecond
	// Потолки трафика: на гигабитном канале шесть секунд — это под гигабайт
	// чужого трафика. Достигнув потолка, замер останавливается раньше срока.
	cfMaxDownload = 300 << 20
	cfMaxUpload   = 150 << 20
	// Размер одного запроса внутри окна. Поток повторяет запросы, пока окно
	// не закончится: соединение остаётся тем же (keep-alive), поэтому разгон
	// TCP между запросами не сбрасывается.
	//
	// Куски намеренно крупные: чем их меньше, тем меньше пауз на ожидание
	// ответа внутри окна и тем дальше сервис от своего лимита по частоте
	// запросов (он отвечает 429, и замер обрывается целиком).
	//
	// Увеличивать дальше нельзя без проверки: __down отвечает 403 на запросы
	// больше примерно 80 МиБ (64 МиБ ещё отдаются, 100 МиБ уже нет), и такой
	// ответ выглядел бы как «канал не работает».
	cfDownChunk = 64 << 20
	cfUpChunk   = 25 << 20
)

// cloudflareSpeedtest выполняет полный замер через Cloudflare и возвращает
// отчёт из одной строки.
func cloudflareSpeedtest(ctx context.Context, onResult func(report.SpeedNode), status func(string, ...any)) (*report.Speedtest, error) {
	ctx, cancel := context.WithTimeout(ctx, nodeTimeout)
	defer cancel()

	// Один клиент на весь замер: keep-alive избавляет от повторных
	// TLS-рукопожатий, которые иначе попали бы в измеренное время.
	client := netutil.Client(netutil.Any, nodeTimeout)
	defer client.CloseIdleConnections()

	status("speedtest: locating the nearest Cloudflare edge")
	row := report.SpeedNode{Name: "Cloudflare"}
	if colo, loc := cfEdge(ctx, client); colo != "" {
		row.Name = "Cloudflare · " + colo
		row.Sponsor = report.JoinNonEmpty(" ", "Cloudflare", loc)
		row.ID = colo
	}

	status("speedtest: %s latency", row.Name)
	latency, err := cfLatency(ctx, client)
	if err != nil {
		return nil, err
	}
	row.LatencyMs = float64(latency.Microseconds()) / 1000

	status("speedtest: %s download", row.Name)
	down, err := cfDownload(ctx, client)
	if err != nil {
		return nil, err
	}
	row.DownMbps = down

	status("speedtest: %s upload", row.Name)
	up, err := cfUpload(ctx, client)
	if err != nil {
		return nil, err
	}
	row.UploadMbps = up

	if row.DownMbps <= 0 || row.UploadMbps <= 0 {
		return nil, errors.New("cloudflare reported zero throughput")
	}
	if onResult != nil {
		onResult(row)
	}
	return &report.Speedtest{Method: MethodCloudflare, Nodes: []report.SpeedNode{row}}, nil
}

// cfEdge спрашивает у Cloudflare, в какой дата-центр мы попали. Ответ —
// текст вида «colo=FRA», в формате key=value по строке. Неудача не фатальна:
// без кода колонии строка просто называется «Cloudflare».
func cfEdge(ctx context.Context, client *http.Client) (colo, loc string) {
	resp, err := netutil.Get(ctx, client, cfBase+"/cdn-cgi/trace", 4<<10, nil)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(resp.Text(), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "colo":
			colo = v
		case "loc":
			loc = v
		}
	}
	return colo, loc
}

// cfLatency берёт минимум из нескольких пустых запросов. Именно минимум, а не
// среднее: единичная задержка на чужой стороне завышает среднее, а нам нужна
// нижняя граница RTT до edge-узла.
func cfLatency(ctx context.Context, client *http.Client) (time.Duration, error) {
	best := time.Duration(0)
	for i := 0; i < 5; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		if _, err := cfTransfer(ctx, client, 0, false, nil); err != nil {
			continue
		}
		if d := time.Since(start); best == 0 || d < best {
			best = d
		}
	}
	if best == 0 {
		return 0, errors.New("speed.cloudflare.com is unreachable")
	}
	return best, nil
}

// cfDownload и cfUpload меряют приём и отдачу за фиксированное окно.
func cfDownload(ctx context.Context, client *http.Client) (float64, error) {
	return cfMeasure(ctx, client, false, cfDownWindow, cfDownChunk, cfMaxDownload)
}

func cfUpload(ctx context.Context, client *http.Client) (float64, error) {
	return cfMeasure(ctx, client, true, cfUpWindow, cfUpChunk, cfMaxUpload)
}

// cfMeasure — замер одного направления через общий движок (см. speedwindow.go).
func cfMeasure(ctx context.Context, client *http.Client, upload bool, length time.Duration, chunk, budget int64) (float64, error) {
	w := window{streams: cfStreams, length: length, warmup: cfWarmup, budget: budget}
	return measureWindow(ctx, w, func(ctx context.Context, moved *atomic.Int64) (int64, error) {
		return cfTransfer(ctx, client, chunk, upload, moved)
	})
}

// cfTransfer выполняет одну передачу и возвращает число прошедших байт,
// попутно прибавляя их к общему счётчику по мере движения — замер за
// фиксированное время должен видеть прогресс, а не только итог.
//
// Тело ответа уходит в io.Discard, а не в память: на 512 МБ VPS буфер на
// десятки мегабайт — это OOM.
func cfTransfer(ctx context.Context, client *http.Client, size int64, upload bool, moved *atomic.Int64) (int64, error) {
	method, url := http.MethodGet, fmt.Sprintf("%s/__down?bytes=%d", cfBase, size)
	var body io.Reader
	if upload {
		method, url = http.MethodPost, cfBase+"/__up"
		body = &zeroReader{left: size, moved: moved}
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", netutil.UserAgent)
	if upload {
		// Длину выставляем явно: иначе Go отправит chunked-кодирование, а
		// оно добавляет к каждому куску служебные байты и смазывает замер.
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Код ответа проверяется ДО чтения тела. Cloudflare отвечает 403 на
	// слишком крупный запрос и при срабатывании защиты от частых обращений,
	// причём тело такого ответа — один байт. Посчитав его как переданные
	// данные, тест показывал бы «0.00 Mbps» вместо внятной ошибки.
	if resp.StatusCode == http.StatusTooManyRequests {
		// Так отвечают на слишком частые прогоны подряд. Формулировка важна:
		// «HTTP 429» в отчёте выглядит как поломка канала, хотя лечится это
		// паузой в несколько минут.
		return 0, errors.New("cloudflare rate limit — try again in a few minutes")
	}
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("cloudflare returned HTTP %d", resp.StatusCode)
	}
	if upload {
		// На отдаче объём передачи — это тело запроса, его уже посчитал
		// zeroReader; ответ пустой.
		_, _ = io.Copy(io.Discard, resp.Body)
		return size, nil
	}
	return io.Copy(countingWriter{moved}, resp.Body)
}

// countingWriter прибавляет прошедшие байты к счётчику и выбрасывает данные.
type countingWriter struct{ n *atomic.Int64 }

func (w countingWriter) Write(p []byte) (int, error) {
	if w.n != nil {
		w.n.Add(int64(len(p)))
	}
	return len(p), nil
}

// zeroReader отдаёт left нулевых байт, ни разу не выделяя буфер под весь
// объём: тело запроса на десятки мегабайт иначе целиком лежало бы в памяти.
type zeroReader struct {
	left  int64
	moved *atomic.Int64
}

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.left {
		p = p[:z.left]
	}
	for i := range p {
		p[i] = 0
	}
	z.left -= int64(len(p))
	if z.moved != nil {
		z.moved.Add(int64(len(p)))
	}
	return len(p), nil
}
