package netcheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"path"
	"sync/atomic"
	"time"

	"github.com/showwin/speedtest-go/speedtest"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
)

// speedookla.go — сам замер против сервера speedtest.net.
//
// Библиотека speedtest-go умеет мерить сама, но её замер здесь не используется,
// и вот почему. Число параллельных соединений она берёт от числа ядер
// (runtime.NumCPU), а этот инструмент запускают в основном на VPS с одним
// ядром — то есть качает она в одно соединение. Плюс кусок в её цикле около
// 2 МБ: на быстром канале он проходит за миллисекунды, и между кусками канал
// простаивает целый RTT. Итог измерялся: на том же плече библиотека показывала
// 53 Мбит/с там, где канал давал 185, а на отдаче 57 против 300 — расхождение
// в 3–5 раз, ровно то, из-за чего цифры не сходились с официальным клиентом.
//
// Поэтому от библиотеки берутся только список серверов, выбор сервера и пинг,
// а приём с отдачей меряются тем же движком, что и Cloudflare
// (см. speedwindow.go): фиксированное окно, отброшенный разгон, несколько
// потоков.

const (
	// ooklaStreams — сколько соединений открывается к серверу. Официальный
	// клиент Ookla качает так же в несколько потоков; на дальних плечах
	// (Токио, Сидней) одно соединение упирается в окно перегрузки задолго до
	// потолка канала.
	ooklaStreams = 8
	// Окна замера. Отдача короче: исходящий трафик VPS обычно тарифицируется,
	// и лить полгигабайта на каждый из девяти городов — перебор.
	ooklaDownWindow = 8 * time.Second
	ooklaUpWindow   = 6 * time.Second
	ooklaWarmup     = 1500 * time.Millisecond
	// Потолки трафика на одну точку. Ограничение нужно ради серверов
	// speedtest.net: их держат добровольцы, и на канале 10 Гбит/с окно в
	// восемь секунд означало бы десяток гигабайт с чужой машины.
	ooklaMaxDownload = 768 << 20
	ooklaMaxUpload   = 384 << 20
	// Размер одной передачи внутри окна.
	//
	// На приём берётся random4000x4000.jpg — файл на 31,6 МБ, который есть на
	// каждом сервере Ookla, от старых PHP-сборок до нынешних. Более новый
	// эндпоинт /download?size= отвечает не везде одинаково: один из проверенных
	// серверов отдавал по нему вдвое меньше запрошенного и вшестеро медленнее,
	// чем тот же файл. Размер выбирать нельзя, но 31,6 МБ и так достаточно,
	// чтобы пауза между запросами не портила замер.
	ooklaDownFile = "random4000x4000.jpg"
	// На отдачу — 16 МиБ за запрос: проверено на серверах в четырёх городах,
	// принимают. Класть больше рискованно, часть сборок обрывает соединение.
	ooklaUpChunk = 16 << 20
)

// ooklaMeasure меряет отдачу и приём против выбранного сервера.
//
// Порядок «сначала отдача» сохранён с прежней реализации: она чаще упирается в
// ограничения сервера, и провал на ней позволяет перейти к следующему
// кандидату, не потратив время на приём.
func ooklaMeasure(ctx context.Context, srv *speedtest.Server, status func(string, ...any), label string) (up, down float64, err error) {
	client := netutil.StreamClient(netutil.Any, nodeTimeout, ooklaStreams)
	defer client.CloseIdleConnections()

	upURL, downURL, err := ooklaEndpoints(ctx, client, srv)
	if err != nil {
		return 0, 0, err
	}

	status("speedtest: %s upload", label)
	up, err = measureWindow(ctx,
		window{streams: ooklaStreams, length: ooklaUpWindow, warmup: ooklaWarmup, budget: ooklaMaxUpload},
		func(ctx context.Context, moved *atomic.Int64) (int64, error) {
			return ooklaTransfer(ctx, client, upURL, ooklaUpChunk, moved)
		})
	if err != nil {
		return 0, 0, err
	}

	status("speedtest: %s download", label)
	down, err = measureWindow(ctx,
		window{streams: ooklaStreams, length: ooklaDownWindow, warmup: ooklaWarmup, budget: ooklaMaxDownload},
		func(ctx context.Context, moved *atomic.Int64) (int64, error) {
			return ooklaTransfer(ctx, client, downURL, 0, moved)
		})
	if err != nil {
		return 0, 0, err
	}
	return up, down, nil
}

// ooklaEndpoints выясняет, куда лить и откуда качать.
//
// Адрес из списка серверов — это не обязательно тот адрес, который принимает
// данные: сборки на ooklaserver.net отвечают на него редиректом 307 на свой
// HTTPS-хост. Редирект надо разрешить заранее, запросом HEAD: тело POST через
// редирект Go не перепошлёт (оно одноразовое), и попытка лить на исходный
// адрес обрывается сервером на первых мегабайтах.
func ooklaEndpoints(ctx context.Context, client *http.Client, srv *speedtest.Server) (upURL, downURL string, err error) {
	upURL = srv.URL
	if resolved := resolveRedirect(ctx, client, upURL); resolved != "" {
		upURL = resolved
	}
	u, err := url.Parse(upURL)
	if err != nil {
		return "", "", fmt.Errorf("bad server URL: %w", err)
	}
	// В списке серверов адрес указывает на upload.php; файлы для приёма лежат
	// рядом, в том же каталоге.
	u.Path = path.Join(path.Dir(u.Path), ooklaDownFile)
	return upURL, u.String(), nil
}

// resolveRedirect возвращает адрес, на котором мы оказываемся после
// редиректов, или пустую строку, если спросить не удалось: тогда работаем по
// исходному адресу, а ошибка вылезет уже на самом замере.
func resolveRedirect(ctx context.Context, client *http.Client, target string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", netutil.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.Request == nil || resp.Request.URL == nil {
		return ""
	}
	return resp.Request.URL.String()
}

// ooklaTransfer выполняет одну передачу: size > 0 — отдача тела такого
// размера, size == 0 — приём файла целиком.
//
// Тело ответа уходит в io.Discard, а не в память: на 512 МБ VPS буфер на
// десятки мегабайт — это OOM.
func ooklaTransfer(ctx context.Context, client *http.Client, target string, size int64, moved *atomic.Int64) (int64, error) {
	method, body := http.MethodGet, io.Reader(nil)
	if size > 0 {
		method = http.MethodPost
	} else {
		// Промежуточные прокси и кеши не должны отдавать файл из памяти —
		// иначе замеряется не канал до сервера, а канал до кеша.
		target = fmt.Sprintf("%s?x=%d", target, rand.Int63())
	}
	if size > 0 {
		body = &zeroReader{left: size, moved: moved}
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", netutil.UserAgent)
	if size > 0 {
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
	// Код ответа проверяется ДО чтения тела: страница ошибки — это несколько
	// сотен байт, и, посчитав их как переданные данные, замер показал бы
	// правдоподобную ерунду вместо отказа. Библиотека этой проверки не делает,
	// и сервер, потерявший файлы для приёма, выглядел у неё «медленным».
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}
	if size > 0 {
		// На отдаче объём передачи — это тело запроса, его уже посчитал
		// zeroReader; ответ пустой.
		_, _ = io.Copy(io.Discard, resp.Body)
		return size, nil
	}
	n, err := io.Copy(countingWriter{moved}, resp.Body)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return 0, errors.New("server sent an empty body")
	}
	return n, nil
}
