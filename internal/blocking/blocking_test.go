package blocking

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/report"
)

// blocking_test.go — ступени проверки на localhost. Сеть провайдера здесь
// изображают сами серверы: один молча замирает посреди тела, другой рвёт
// соединение на ClientHello, третий показывает чужой сертификат.

// noLookup — резолвер, которого тест не ждёт: цели с Addr в DNS не ходят.
func noLookup(context.Context, string) ([]string, error) {
	return nil, errors.New("unexpected DNS lookup")
}

func fixed(ips ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) { return ips, nil }
}

func testProber(port string, roots *x509.CertPool) *prober {
	return &prober{
		port: port, roots: roots, lookup: noLookup, resolve: noLookup,
		dnsTimeout: time.Second, dialTimeout: time.Second, tlsTimeout: time.Second,
		respTimeout: time.Second, idleTimeout: 200 * time.Millisecond, bodyWindow: 2 * time.Second,
	}
}

// tlsServer поднимает HTTPS-сервер и проверку, доверяющую его сертификату.
// Сертификат httptest выписан на example.com — это имя и уходит в SNI.
func tlsServer(t *testing.T, h http.HandlerFunc) *prober {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	// Отказ клиента от сертификата сервер пишет в лог; в выводе тестов это шум.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return testProber(port, pool)
}

func local(host, path string) Target {
	return Target{Service: "svc", Host: host, Addr: "127.0.0.1", Path: path}
}

func payload(n int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, n)) }
}

func TestProbeReachable(t *testing.T) {
	p := tlsServer(t, payload(100<<10))
	got := p.probe(context.Background(), local("example.com", "/"))
	if got.Status != statusOK || got.HTTP != 200 || got.Stage != "" {
		t.Errorf("probe = %+v, want ok with HTTP 200", got)
	}
}

// Так выглядит замедление по ТСПУ: первые килобайты приходят, дальше поток
// молчит. Это не блокировка и не неудача, а отдельный вердикт.
func TestProbeStalledTransfer(t *testing.T) {
	release := make(chan struct{})
	p := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048576")
		_, _ = w.Write(make([]byte, 20<<10))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) }) // раньше srv.Close: иначе тот ждал бы обработчик

	got := p.probe(context.Background(), local("example.com", "/"))
	if got.Status != statusThrottled || got.Stage != "http" || !strings.HasPrefix(got.Detail, "stalled after") {
		t.Errorf("probe = %+v, want a throttled/stalled verdict", got)
	}
}

func TestProbeHTTP451(t *testing.T) {
	p := tlsServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnavailableForLegalReasons)
	})
	got := p.probe(context.Background(), local("example.com", "/"))
	if got.Status != statusBlocked || got.Detail != "HTTP 451" {
		t.Errorf("probe = %+v, want blocked by HTTP 451", got)
	}
}

// Провайдерская заглушка отвечает своим сертификатом: имя в нём не совпадает
// с запрошенным.
func TestProbeForgedCertificate(t *testing.T) {
	p := tlsServer(t, payload(10))
	got := p.probe(context.Background(), local("www.instagram.com", "/"))
	if got.Status != statusBlocked || got.Stage != "tls" || got.Detail != "certificate mismatch" {
		t.Errorf("probe = %+v, want blocked at tls by certificate", got)
	}
}

// DPI дожидается ClientHello с именем сервиса и рвёт соединение.
func TestProbeResetOnClientHello(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*net.TCPConn).SetLinger(0) // закрытие с RST, а не FIN
			_, _ = c.Read(make([]byte, 4096))
			_ = c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	got := testProber(port, nil).probe(context.Background(), local("discord.com", "/"))
	if got.Status != statusBlocked || got.Stage != "tls" {
		t.Errorf("probe = %+v, want blocked at tls", got)
	}
}

func TestProbeTCPRefused(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_ = ln.Close()

	got := testProber(port, nil).probe(context.Background(), local("api.telegram.org", "/"))
	if got.Status != statusBlocked || got.Stage != "tcp" {
		t.Errorf("probe = %+v, want blocked at tcp", got)
	}
}

// Резолвер провайдера подменил адрес, а настоящий хост отвечает: вердикт —
// блокировка по DNS, и в строке сказано, что сам адрес доступен.
func TestProbeSpoofedDNS(t *testing.T) {
	p := tlsServer(t, payload(10))
	p.lookup, p.resolve = fixed("10.10.34.34"), fixed("127.0.0.1")

	got := p.probe(context.Background(), Target{Service: "svc", Host: "example.com", Path: "/"})
	if got.Status != statusBlocked || got.Stage != "dns" || got.Detail != "DNS spoofed: 10.10.34.34 (IP reachable)" {
		t.Errorf("probe = %+v, want a DNS spoof verdict", got)
	}
}

func TestDNSVerdicts(t *testing.T) {
	nx := func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}
	p := testProber("443", nil)

	// Имя существует (DoH знает адрес), а системный резолвер его прячет.
	p.lookup, p.resolve = nx, fixed("203.0.113.7")
	ips, block, err := p.dns(context.Background(), "x")
	if err != nil || block != "DNS: NXDOMAIN" || len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Errorf("hidden name: ips=%v block=%q err=%v", ips, block, err)
	}

	// Не знает никто: это не блокировка, сравнить не с чем.
	p.lookup, p.resolve = nx, nx
	if _, block, err := p.dns(context.Background(), "x"); err == nil || block != "" {
		t.Errorf("unknown name: block=%q err=%v, want an error", block, err)
	}

	// Обычный публичный ответ эталон не трогает: CDN раздают разные адреса.
	p.lookup, p.resolve = fixed("203.0.113.7"), noLookup
	if ips, block, err := p.dns(context.Background(), "x"); err != nil || block != "" || ips[0] != "203.0.113.7" {
		t.Errorf("normal answer: ips=%v block=%q err=%v", ips, block, err)
	}

	// Подмена на 0.0.0.0 при недоступном эталоне — всё равно подмена.
	p.lookup, p.resolve = fixed("0.0.0.0"), nx
	if ips, block, err := p.dns(context.Background(), "x"); err != nil || block != "DNS spoofed: 0.0.0.0" || len(ips) != 0 {
		t.Errorf("spoof without reference: ips=%v block=%q err=%v", ips, block, err)
	}
}

func TestRunGroupsByService(t *testing.T) {
	p := tlsServer(t, payload(10))
	p.controls = []Target{local("example.com", "/")}
	targets := []Target{
		{Service: "A", Host: "example.com", Addr: "127.0.0.1", Path: "/"},
		{Service: "B", Host: "example.com", Addr: "127.0.0.1", Path: "/"},
		{Service: "B", Host: "blocked.example", Addr: "127.0.0.1", Path: "/"},
	}
	got, err := p.run(context.Background(), targets, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Services) != 2 || got.Services[0].Name != "A" || len(got.Services[1].Probes) != 2 {
		t.Fatalf("services = %+v", got.Services)
	}
	if got.Services[0].Status != statusOK || got.Services[1].Status != statusPartial {
		t.Errorf("verdicts = %q, %q; want ok, partial", got.Services[0].Status, got.Services[1].Status)
	}
}

// Без связи с миром всё выглядело бы заблокированным. Такой прогон обязан
// стать ошибкой теста, а не таблицей из «Blocked».
func TestRunWithoutConnectivityFails(t *testing.T) {
	p := tlsServer(t, payload(10))
	p.controls = []Target{local("unreachable.example", "/")}
	if _, err := p.run(context.Background(), []Target{local("example.com", "/")}, func(string, ...any) {}); err == nil {
		t.Error("run succeeded although every control host failed")
	}
}

func TestVerdict(t *testing.T) {
	probe := func(ss ...string) []report.BlockProbe {
		var out []report.BlockProbe
		for _, s := range ss {
			out = append(out, report.BlockProbe{Status: s})
		}
		return out
	}
	cases := []struct {
		in   []report.BlockProbe
		want string
	}{
		{probe(statusOK, statusOK), statusOK},
		{probe(statusOK, statusFailed), statusOK},
		{probe(statusBlocked, statusBlocked), statusBlocked},
		{probe(statusBlocked, statusThrottled), statusBlocked},
		{probe(statusThrottled, statusFailed), statusThrottled},
		{probe(statusOK, statusThrottled), statusPartial},
		{probe(statusFailed, statusFailed), statusFailed},
	}
	for _, c := range cases {
		if got := verdict(c.in); got != c.want {
			t.Errorf("verdict(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Список целей правится руками вслед за сервисами; ловим очевидные ошибки.
func TestTargets(t *testing.T) {
	seen := map[string]bool{}
	for _, tg := range Targets {
		seen[tg.Service] = true
		if tg.Host == "" || (!tg.TCPOnly && !strings.HasPrefix(tg.Path, "/")) {
			t.Errorf("incomplete target %+v", tg)
		}
		if tg.Addr != "" && net.ParseIP(tg.Addr).To4() == nil {
			t.Errorf("%s: Addr %q is not IPv4", tg.Host, tg.Addr)
		}
		if tg.TCPOnly && tg.Addr == "" {
			t.Errorf("%s: a TCP-only target needs a fixed address", tg.Host)
		}
	}
	for _, s := range []string{"Telegram", "Instagram", "YouTube", "Discord", "TikTok"} {
		if !seen[s] {
			t.Errorf("no target for %s", s)
		}
	}
}
