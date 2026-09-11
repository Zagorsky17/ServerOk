// Пакет blocking проверяет, не заблокированы ли с этого сервера мессенджеры и
// соцсети: Telegram, Instagram, YouTube, Discord, TikTok.
//
// Вопрос здесь другой, чем в пакете unblock. Там сервис отвечает, и важно,
// какой регион он присваивает адресу. Здесь важно, доходят ли пакеты вообще:
// блокировки на уровне страны (РКН, GFW, иранский фильтр) делаются в сети
// провайдера, и сам сервис о них ничего не знает. Поэтому соединение
// проходится по ступеням, и вердикт называет ту, на которой оно сломалось:
//
//	dns  — системный резолвер не отдаёт адрес или отдаёт подставной, хотя
//	       независимый DoH-резолвер знает настоящий;
//	tcp  — адрес не принимает соединение (блокировка по IP);
//	tls  — соединение рвётся или зависает на ClientHello (DPI увидел имя
//	       сервиса в SNI) либо сертификат чужой (страница-заглушка);
//	http — ответа нет, пришёл 451 или поток замер после первых килобайт —
//	       так выглядит замедление.
//
// Ступень важнее самого «заблокировано»: от неё зависит, поможет ли смена
// DNS или нужен туннель.
//
// Проверяется только IPv4, как и в unblock: по нему идёт почти весь трафик.
package blocking

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
	"github.com/Zagorsky17/ServerOk/internal/report"
)

// Target — один проверяемый адрес сервиса.
type Target struct {
	Service string
	Host    string // имя для DNS и SNI
	Path    string // что запрашивать
	Addr    string // готовый IPv4 вместо DNS
	Label   string // подпись в отчёте, если Host ничего не скажет читателю
	TCPOnly bool   // по адресу говорят не на HTTPS, проверяется только TCP
}

// Targets — что проверяется, в порядке вывода. У каждого сервиса несколько
// адресов: блокируют часто не весь сервис, а его CDN или API, и одна главная
// страница этого не покажет.
//
// Path выбран так, чтобы ответ был заметно больше 16–20 КБ: на этом пороге
// российские ТСПУ замораживают соединение, и на коротком ответе замедление
// не видно. Отсюда jpg-обложка на i.ytimg.com и report_mapping (~1,5 МБ).
var Targets = []Target{
	{Service: "Telegram", Host: "api.telegram.org", Path: "/"},
	{Service: "Telegram", Host: "telegram.org", Path: "/"},
	// DC2 (Амстердам) говорит на MTProto, а не на HTTPS. TCP ловит
	// блокировку по IP, но не DPI по сигнатуре протокола — поэтому в строке
	// так и написано: TCP.
	{Service: "Telegram", Host: "149.154.167.51", Addr: "149.154.167.51", Label: "DC2 149.154.167.51", TCPOnly: true},
	{Service: "Instagram", Host: "www.instagram.com", Path: "/"},
	{Service: "Instagram", Host: "scontent.cdninstagram.com", Path: "/"},
	{Service: "YouTube", Host: "www.youtube.com", Path: "/"},
	{Service: "YouTube", Host: "i.ytimg.com", Path: "/vi/dQw4w9WgXcQ/maxresdefault.jpg"},
	// googlevideo.com — видео-CDN. Замедление YouTube настраивают именно на
	// это имя: страница открывается, а видео стоит.
	{Service: "YouTube", Host: "redirector.googlevideo.com", Path: "/report_mapping"},
	{Service: "Discord", Host: "discord.com", Path: "/"},
	{Service: "Discord", Host: "gateway.discord.gg", Path: "/"},
	{Service: "Discord", Host: "cdn.discordapp.com", Path: "/"},
	{Service: "TikTok", Host: "www.tiktok.com", Path: "/"},
	{Service: "TikTok", Host: "www.tiktokv.com", Path: "/"},
}

// controls — контрольные адреса. Если не отвечает ни один, у сервера просто
// нет исходящего HTTPS, и «Blocked» по всем сервисам было бы враньём.
// google.com на эту роль не годится: в Китае он закрыт сам.
var controls = []Target{
	{Service: "control", Host: "www.microsoft.com", Path: "/"},
	{Service: "control", Host: "www.apple.com", Path: "/"},
}

// dohEndpoints — эталонные резолверы. Адреса заданы IP-литералами: сертификаты
// у обоих выписаны и на IP, так что обращение к ним не зависит от системного
// DNS, которому здесь как раз не доверяют.
var dohEndpoints = []string{
	"https://1.1.1.1/dns-query?type=A&name=",
	"https://8.8.8.8/resolve?type=A&name=",
}

// Вердикты. partial бывает только у сервиса целиком: часть адресов доступна.
const (
	statusOK        = "ok"
	statusBlocked   = "blocked"
	statusThrottled = "throttled"
	statusPartial   = "partial"
	statusFailed    = "failed"
)

const (
	// bodyCap — сколько тела читать. Порог заморозки ~16–20 КБ, так что
	// 256 КБ хватает с запасом, а мегабайтные страницы не тянутся целиком.
	bodyCap = 256 << 10
	// Скорость считается только на объёме от rateMinBytes: меньше — это ещё
	// разгон TCP, а не канал. Медленнее slowRate на таком объёме — уже не
	// «далёкий сервер», а замедление: даже на 250 мс RTT 256 КБ приходят за
	// секунду с небольшим.
	rateMinBytes = 64 << 10
	slowRate     = 64 << 10 // байт в секунду
)

// prober — одна настройка проверки. Резолверы и корни сертификатов вынесены
// в поля, чтобы тесты могли поднять всё на localhost.
type prober struct {
	port     string
	lookup   func(ctx context.Context, host string) ([]string, error) // системный резолвер
	resolve  func(ctx context.Context, host string) ([]string, error) // эталонный, через DoH
	roots    *x509.CertPool                                           // nil — системные
	controls []Target

	dnsTimeout  time.Duration
	dialTimeout time.Duration
	tlsTimeout  time.Duration
	respTimeout time.Duration // от запроса до заголовков ответа
	idleTimeout time.Duration // пауза в потоке, после которой он считается замершим
	bodyWindow  time.Duration // лимит на чтение тела целиком
}

func defaultProber() *prober {
	return &prober{
		port:        "443",
		lookup:      systemLookup,
		resolve:     dohLookup,
		controls:    controls,
		dnsTimeout:  5 * time.Second,
		dialTimeout: 6 * time.Second,
		tlsTimeout:  6 * time.Second,
		respTimeout: 8 * time.Second,
		idleTimeout: 4 * time.Second,
		bodyWindow:  10 * time.Second,
	}
}

// Run проверяет все адреса параллельно и собирает их по сервисам в порядке
// объявления. Ошибка возвращается, только если не ответил ни один
// контрольный адрес — тогда судить о блокировках не по чему.
func Run(ctx context.Context, status func(string, ...any)) (*report.Blocking, error) {
	return defaultProber().run(ctx, Targets, status)
}

func (p *prober) run(ctx context.Context, targets []Target, status func(string, ...any)) (*report.Blocking, error) {
	all := append(append([]Target(nil), p.controls...), targets...)
	results := make([]report.BlockProbe, len(all))

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i, t := range all {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[i] = p.probe(ctx, t)

			mu.Lock()
			done++
			status("blocking: %d/%d endpoints checked", done, len(all))
			mu.Unlock()
		}(i, t)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	nc := len(p.controls)
	if nc > 0 && !anyReachable(results[:nc]) {
		c := results[0]
		return nil, fmt.Errorf("control host %s unreachable (%s): no working outbound HTTPS over IPv4, blocking cannot be judged",
			c.Host, c.Detail)
	}
	return group(targets, results[nc:]), nil
}

// probe проводит один адрес через все ступени.
func (p *prober) probe(ctx context.Context, t Target) report.BlockProbe {
	ips, dnsBlock := []string{t.Addr}, ""
	if t.Addr == "" {
		var err error
		ips, dnsBlock, err = p.dns(ctx, t.Host)
		if err != nil {
			return report.BlockProbe{Host: label(t), Status: statusFailed, Stage: "dns", Detail: "DNS: " + err.Error()}
		}
		if len(ips) == 0 {
			return report.BlockProbe{Host: label(t), Status: statusBlocked, Stage: "dns", Detail: dnsBlock}
		}
	}
	res := p.transport(ctx, t, ips)
	if dnsBlock != "" {
		// Резолвер врёт, но сам адрес может отвечать — тогда достаточно
		// сменить DNS, и это стоит сказать прямо.
		detail := dnsBlock
		if res.Status == statusOK {
			detail += " (IP reachable)"
		}
		res.Status, res.Stage, res.Detail = statusBlocked, "dns", detail
	}
	return res
}

// dns возвращает адреса для соединения. block непуст, если системный
// резолвер соврал или промолчал, а эталонный знает настоящий адрес: тогда ips
// — адреса эталона, чтобы проверить и сам хост. err — оба резолвера не знают
// имени; сравнивать не с чем, и это неудача проверки, а не блокировка.
func (p *prober) dns(ctx context.Context, host string) (ips []string, block string, err error) {
	dctx, cancel := context.WithTimeout(ctx, p.dnsTimeout)
	sys, sysErr := p.lookup(dctx, host)
	cancel()
	if sysErr == nil && len(sys) == 0 {
		sysErr = errors.New("no A records")
	}
	if sysErr == nil && !allBogus(sys) {
		return sys, "", nil
	}

	rctx, cancel := context.WithTimeout(ctx, p.dnsTimeout)
	ref, refErr := p.resolve(rctx, host)
	cancel()
	if refErr == nil && len(ref) == 0 {
		refErr = errors.New("no A records")
	}
	switch {
	case sysErr == nil:
		// Адрес из частной или служебной сети настоящему публичному сервису
		// не выдают — это подмена, даже если сверить не с чем.
		block = "DNS spoofed: " + sys[0]
	case refErr != nil:
		return nil, "", errors.New(dnsReason(sysErr))
	default:
		block = "DNS: " + dnsReason(sysErr)
	}
	if refErr != nil {
		return nil, block, nil
	}
	return ref, block, nil
}

// transport проходит TCP, TLS и HTTP. Второй адрес пробуется, только если не
// удался TCP: блокировка по SNI одинакова для всех адресов, и лишняя попытка
// лишь удвоила бы ожидание.
func (p *prober) transport(ctx context.Context, t Target, ips []string) report.BlockProbe {
	var first report.BlockProbe
	for i, ip := range ips {
		if i == 2 {
			break
		}
		r := p.attempt(ctx, t, ip)
		if r.Status == statusOK || r.Stage != "tcp" {
			return r
		}
		if i == 0 {
			first = r
		}
	}
	return first
}

func (p *prober) attempt(ctx context.Context, t Target, ip string) report.BlockProbe {
	res := report.BlockProbe{Host: label(t), IP: ip}

	dctx, cancel := context.WithTimeout(ctx, p.dialTimeout)
	start := time.Now()
	conn, err := netutil.Dialer(netutil.IPv4, p.dialTimeout).DialContext(dctx, string(netutil.IPv4), net.JoinHostPort(ip, p.port))
	cancel()
	if err != nil {
		return fail(res, "tcp", err)
	}
	defer conn.Close()
	res.RTTMs = float64(time.Since(start).Microseconds()) / 1000
	if t.TCPOnly {
		res.Status, res.Detail = statusOK, fmt.Sprintf("TCP · %.0f ms", res.RTTMs)
		return res
	}

	tc := tls.Client(conn, &tls.Config{
		ServerName: t.Host,
		// Только HTTP/1.1: запрос ниже пишется вручную, без HTTP/2.
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
		RootCAs:    p.roots,
	})
	hctx, cancel := context.WithTimeout(ctx, p.tlsTimeout)
	err = tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return fail(res, "tls", err)
	}
	return p.fetch(ctx, tc, t, res)
}

// fetch отправляет запрос по уже открытому TLS-соединению и читает ответ.
// http.Client здесь не годится: он скрывает, на какой ступени сломалось
// соединение, и не даёт заметить, что поток замер посреди тела.
func (p *prober) fetch(ctx context.Context, conn net.Conn, t Target, res report.BlockProbe) report.BlockProbe {
	// Дедлайны ниже о контексте не знают — без этого Ctrl+C ждал бы конца
	// окна чтения.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	req, err := http.NewRequest(http.MethodGet, "https://"+t.Host+t.Path, nil)
	if err != nil {
		res.Status, res.Stage, res.Detail = statusFailed, "http", err.Error()
		return res
	}
	req.Header.Set("User-Agent", netutil.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	// Без сжатия: сжатая страница может уложиться в порог заморозки, и
	// замедление останется незамеченным.
	req.Header.Set("Accept-Encoding", "identity")
	req.Close = true

	_ = conn.SetDeadline(time.Now().Add(p.respTimeout))
	if err := req.Write(conn); err != nil {
		return fail(res, "http", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		if isTimeout(err) {
			res.Status, res.Stage, res.Detail = statusBlocked, "http", "no response after TLS"
			return res
		}
		return fail(res, "http", err)
	}
	defer resp.Body.Close()
	res.HTTP = resp.StatusCode
	if resp.StatusCode == http.StatusUnavailableForLegalReasons {
		res.Status, res.Stage, res.Detail = statusBlocked, "http", "HTTP 451"
		return res
	}

	tr := p.drain(conn, resp.Body)
	kb := tr.bytes >> 10
	rate := 0.0
	if tr.bytes >= rateMinBytes && tr.elapsed > 0 {
		rate = float64(tr.bytes) / tr.elapsed.Seconds()
		res.KBps = rate / 1024
	}
	switch {
	case tr.stalled && tr.bytes == 0:
		res.Status, res.Stage, res.Detail = statusThrottled, "http", "stalled after headers"
	case tr.stalled:
		res.Status, res.Stage, res.Detail = statusThrottled, "http", fmt.Sprintf("stalled after %d KB", kb)
	case tr.slow:
		res.Status, res.Stage, res.Detail = statusThrottled, "http", fmt.Sprintf("slow: %d KB in %.0f s", kb, tr.elapsed.Seconds())
	case tr.err != nil && errors.Is(tr.err, syscall.ECONNRESET):
		res.Status, res.Stage, res.Detail = statusBlocked, "http", fmt.Sprintf("reset after %d KB", kb)
	case tr.err != nil:
		return fail(res, "http", tr.err)
	case rate > 0 && rate < slowRate:
		res.Status, res.Stage, res.Detail = statusThrottled, "http", "slow: "+rateText(rate)
	default:
		res.Status = statusOK
		res.Detail = fmt.Sprintf("HTTP %d · %.0f ms", resp.StatusCode, res.RTTMs)
		if rate > 0 {
			res.Detail += " · " + rateText(rate)
		}
	}
	return res
}

// transfer — итог чтения тела.
type transfer struct {
	bytes   int64
	elapsed time.Duration
	stalled bool // поток замолчал дольше idleTimeout
	slow    bool // поток шёл, но не уложился в bodyWindow
	err     error
}

// drain читает тело до bodyCap, продлевая дедлайн на каждом куске: так
// остановка потока ловится за idleTimeout, а не за всё окно.
func (p *prober) drain(conn net.Conn, body io.Reader) transfer {
	var tr transfer
	buf := make([]byte, 32<<10)
	start := time.Now()
	end := start.Add(p.bodyWindow)
	for tr.bytes < bodyCap {
		dl := time.Now().Add(p.idleTimeout)
		if dl.After(end) {
			dl = end
		}
		_ = conn.SetReadDeadline(dl)
		n, err := body.Read(buf)
		tr.bytes += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			if isTimeout(err) {
				tr.slow = !time.Now().Before(end)
				tr.stalled = !tr.slow
			} else {
				tr.err = err
			}
			break
		}
	}
	tr.elapsed = time.Since(start)
	return tr
}

// fail переводит сетевую ошибку ступени в вердикт. Таймаут, сброс и обрыв на
// TCP или TLS — это то, как выглядит блокировка изнутри: DPI либо молча
// выбрасывает пакеты, либо шлёт RST от имени сервера. Чужой сертификат —
// провайдер подставил страницу-заглушку. Всё непонятное — failed, а не
// blocked: выдумывать блокировку нельзя.
func fail(res report.BlockProbe, stage string, err error) report.BlockProbe {
	name := strings.ToUpper(stage)
	res.Stage, res.Status = stage, statusBlocked
	var certErr *tls.CertificateVerificationError
	switch {
	case isTimeout(err):
		res.Detail = name + " timeout"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		res.Detail = name + " reset"
	case errors.Is(err, syscall.ECONNREFUSED):
		res.Detail = name + " refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		res.Detail = name + " unreachable"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		res.Detail = name + " dropped"
	case errors.As(err, &certErr):
		res.Detail = "certificate mismatch"
	default:
		res.Status = statusFailed
		res.Detail = report.Truncate(name+": "+err.Error(), 30)
	}
	return res
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// group собирает результаты по сервисам в порядке объявления целей.
func group(targets []Target, probes []report.BlockProbe) *report.Blocking {
	out := &report.Blocking{}
	idx := map[string]int{}
	for i, t := range targets {
		j, ok := idx[t.Service]
		if !ok {
			j = len(out.Services)
			idx[t.Service] = j
			out.Services = append(out.Services, report.BlockService{Name: t.Service})
		}
		out.Services[j].Probes = append(out.Services[j].Probes, probes[i])
	}
	for i := range out.Services {
		out.Services[i].Status = verdict(out.Services[i].Probes)
	}
	return out
}

// verdict сводит адреса сервиса в один статус. Неудавшиеся проверки не
// голосуют: они говорят о нас, а не о сервисе.
func verdict(probes []report.BlockProbe) string {
	var ok, blocked, throttled int
	for _, p := range probes {
		switch p.Status {
		case statusOK:
			ok++
		case statusBlocked:
			blocked++
		case statusThrottled:
			throttled++
		}
	}
	switch {
	case ok+blocked+throttled == 0:
		return statusFailed
	case blocked+throttled == 0:
		return statusOK
	case ok > 0:
		return statusPartial
	case blocked > 0:
		return statusBlocked
	default:
		return statusThrottled
	}
}

// anyReachable — ответил ли хоть один адрес дальше TLS.
func anyReachable(probes []report.BlockProbe) bool {
	for _, p := range probes {
		if p.Status == statusOK || p.Status == statusThrottled {
			return true
		}
	}
	return false
}

// allBogus — все ли адреса из частных и служебных сетей. Такие ответы для
// публичного сервиса — верный признак подмены DNS (0.0.0.0, 127.0.0.1,
// 10.x у провайдерских заглушек).
func allBogus(ips []string) bool {
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
			return false
		}
	}
	return true
}

func dnsReason(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsNotFound:
			return "NXDOMAIN"
		case de.IsTimeout:
			return "timeout"
		}
		return report.Truncate(de.Err, 24)
	}
	return report.Truncate(err.Error(), 24)
}

func label(t Target) string {
	if t.Label != "" {
		return t.Label
	}
	return t.Host
}

func rateText(bps float64) string {
	if bps >= 1<<20 {
		return fmt.Sprintf("%.1f MB/s", bps/(1<<20))
	}
	return fmt.Sprintf("%.0f KB/s", bps/1024)
}

func systemLookup(ctx context.Context, host string) ([]string, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, err
}

// dohLookup спрашивает A-записи у эталонных резолверов по DNS-over-HTTPS.
// Их ответ — такой же недоверенный ввод, поэтому в дело идут только
// разобранные IPv4-адреса.
func dohLookup(ctx context.Context, host string) ([]string, error) {
	c := netutil.Client(netutil.IPv4, 5*time.Second)
	defer c.CloseIdleConnections()
	var lastErr error
	for _, ep := range dohEndpoints {
		resp, err := netutil.Get(ctx, c, ep+url.QueryEscape(host), 64<<10,
			map[string]string{"Accept": "application/dns-json"})
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Status != http.StatusOK {
			lastErr = fmt.Errorf("DoH HTTP %d", resp.Status)
			continue
		}
		var ans struct {
			Status int
			Answer []struct {
				Type int    `json:"type"`
				Data string `json:"data"`
			}
		}
		if err := json.Unmarshal(resp.Body, &ans); err != nil {
			lastErr = err
			continue
		}
		if ans.Status == 3 { // RCODE 3 — имени не существует
			return nil, errors.New("NXDOMAIN")
		}
		var ips []string
		for _, a := range ans.Answer {
			if ip := net.ParseIP(a.Data); a.Type == 1 && ip != nil && ip.To4() != nil {
				ips = append(ips, ip.String())
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
		lastErr = errors.New("no A records")
	}
	return nil, lastErr
}
