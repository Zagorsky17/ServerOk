// Пакет netutil — общий сетевой фундамент для всех тестов, которые ходят
// наружу (ipinfo, unblock, netcheck, sysinfo).
//
// Он решает три задачи:
//  1. Привязка исходящих соединений к конкретной версии IP (Family). Обычный
//     http.Client сам выбирает IPv4/IPv6, а нам нужно уметь спросить «что
//     видит мир по IPv4» и отдельно «что по IPv6».
//  2. Единый GET, который читает тело с ограничением, закрывает его и отдаёт
//     ровно то, что нужно вызывающему (Response) — чтобы нигде в проекте не
//     осталось незакрытых Body и чтения ответов без лимита.
//  3. Быстрая проверка «отвечает ли TCP-порт» (TCPReachable), которой
//     пользуются проверка связности и отсев мёртвых speedtest-серверов.
package netutil

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// UserAgent подставляется в каждый исходящий запрос.
//
// ВАЖНО для ревью: строка обязана выглядеть как обычный браузер. Netflix и
// другие стриминговые сайты отдают неизвестному User-Agent другую страницу —
// без привязки к региону, и проверка разблокировки начинает показывать чужую
// страну. Это было воспроизведено: с суффиксом "ServerOk" в UA Netflix
// отвечал requestCountry=US при немецком IP. Не добавляйте сюда название
// продукта.
const UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

// Family — версия IP, которой пользуется соединение. Значения совпадают с
// именами сетей пакета net, поэтому их можно передавать в Dial напрямую.
type Family string

const (
	Any  Family = "tcp"  // как решит резолвер (обычно IPv6, если он есть)
	IPv4 Family = "tcp4" // только IPv4
	IPv6 Family = "tcp6" // только IPv6
)

// Dialer возвращает диалер, жёстко привязанный к указанной версии IP.
func Dialer(f Family, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if f == IPv4 {
		// Отключаем Happy Eyeballs: при явном tcp4 параллельная попытка по
		// IPv6 не нужна и только путает тайминги.
		d.FallbackDelay = -1
	}
	return d
}

// Client собирает HTTP-клиент, все соединения которого идут по заданной
// версии IP.
//
// Клиент одноразовый по смыслу: тот, кто делает несколько запросов, должен
// сделать defer c.CloseIdleConnections(), иначе висящие keep-alive соединения
// живут до конца процесса.
func Client(f Family, timeout time.Duration) *http.Client {
	return StreamClient(f, timeout, 0)
}

// StreamClient — то же самое, но для замеров скорости: streams параллельных
// соединений к одному хосту должны переживать паузу между запросами.
//
// Без этого http.Transport держит про запас всего два простаивающих соединения
// на хост (DefaultMaxIdleConnsPerHost = 2), и в остальных потоках каждый
// следующий кусок уезжает по свежему TCP-соединению — то есть заново с начала
// разгона. Чем длиннее плечо, тем сильнее такой замер занижает скорость.
//
// streams <= 0 означает «обычный клиент», с умолчаниями транспорта.
func StreamClient(f Family, timeout time.Duration, streams int) *http.Client {
	network := string(f)
	if network == "" {
		network = "tcp"
	}
	d := Dialer(f, timeout)
	tr := &http.Transport{
		// Подменяем набор сети: адрес http.Transport передаёт нам как есть,
		// а версию IP навязываем мы.
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          16,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if streams > 0 {
		tr.MaxIdleConnsPerHost = streams
		if tr.MaxIdleConns < streams {
			tr.MaxIdleConns = streams
		}
	}
	// Timeout на клиенте — общий лимит на запрос целиком, включая чтение тела.
	return &http.Client{Transport: tr, Timeout: timeout}
}

// Response — то, что остаётся от HTTP-ответа после Get: тело уже прочитано и
// закрыто, поэтому возвращать *http.Response было бы ловушкой (его Body уже
// нельзя читать). Здесь ровно три вещи, которые нужны проверкам: код ответа,
// финальный URL (после редиректов — по нему определяется локаль у Netflix) и
// байты тела.
type Response struct {
	Status int
	URL    *url.URL
	Body   []byte
}

// Text возвращает тело строкой. Nil-приёмник допустим: так вызывающему не
// нужно проверять указатель перед разбором.
func (r *Response) Text() string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

// FinalURL возвращает URL после всех редиректов или пустую строку.
func (r *Response) FinalURL() string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.String()
}

// Get выполняет GET со стандартными заголовками, читает не более maxBytes тела
// и закрывает его.
//
// Лимит maxBytes — не только защита от «бесконечного» ответа: у проверок
// разблокировки он подобран так, чтобы маркер региона (он лежит глубоко в
// HTML, за сотни килобайт) точно попал в прочитанный кусок. Если урезать
// лимит, регион молча перестанет определяться.
func Get(ctx context.Context, c *http.Client, url string, maxBytes int64, headers map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	out := &Response{Status: resp.StatusCode, Body: body}
	// resp.Request — последний запрос цепочки редиректов, его URL и есть
	// адрес, на котором мы в итоге оказались.
	if resp.Request != nil {
		out.URL = resp.Request.URL
	}
	// Ошибку чтения возвращаем вместе с уже прочитанной частью: вызывающий
	// сам решит, достаточно ли ему этого.
	return out, err
}

// TCPReachable сообщает, принимает ли addr TCP-соединение за отведённое время.
// Используется для проверки связности IPv4/IPv6 и для отбора живых узлов.
func TCPReachable(ctx context.Context, f Family, addr string, timeout time.Duration) bool {
	d := Dialer(f, timeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, string(f), addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
