package netcheck

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/showwin/speedtest-go/speedtest"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
)

// speedookla_test.go — то, что ломалось в замере против speedtest.net:
// неразрешённый редирект на отдаче и страница ошибки, посчитанная как данные.

// TestOoklaEndpoints: адрес из списка серверов отвечает редиректом, и лить
// нужно уже на разрешённый адрес — тело POST через редирект не перепошлётся.
// Файл для приёма при этом берётся из каталога, куда мы в итоге попали.
func TestOoklaEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/speedtest/upload.php" {
			http.Redirect(w, r, "/moved/upload.php", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := netutil.StreamClient(netutil.Any, 5*time.Second, ooklaStreams)
	defer client.CloseIdleConnections()

	up, down, err := ooklaEndpoints(context.Background(), client,
		&speedtest.Server{URL: srv.URL + "/speedtest/upload.php"})
	if err != nil {
		t.Fatalf("ooklaEndpoints: %v", err)
	}
	if want := srv.URL + "/moved/upload.php"; up != want {
		t.Errorf("upload URL = %q, want the resolved %q", up, want)
	}
	if want := srv.URL + "/moved/" + ooklaDownFile; down != want {
		t.Errorf("download URL = %q, want %q", down, want)
	}
}

// TestOoklaEndpointsWithoutRedirect: если сервер не редиректит (а такие есть),
// адрес остаётся исходным.
func TestOoklaEndpointsWithoutRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := netutil.StreamClient(netutil.Any, 5*time.Second, ooklaStreams)
	defer client.CloseIdleConnections()

	up, down, err := ooklaEndpoints(context.Background(), client,
		&speedtest.Server{URL: srv.URL + "/speedtest/upload.php"})
	if err != nil {
		t.Fatalf("ooklaEndpoints: %v", err)
	}
	if want := srv.URL + "/speedtest/upload.php"; up != want {
		t.Errorf("upload URL = %q, want %q", up, want)
	}
	if want := srv.URL + "/speedtest/" + ooklaDownFile; down != want {
		t.Errorf("download URL = %q, want %q", down, want)
	}
}

// TestOoklaTransferRejectsErrorPage — ровно тот случай, из-за которого
// сломанный сервер выглядел просто медленным: на месте файла лежит страница
// ошибки, и её несколько сотен байт нельзя засчитывать как переданные данные.
func TestOoklaTransferRejectsErrorPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(strings.Repeat("not found\n", 40)))
	}))
	defer srv.Close()

	client := netutil.StreamClient(netutil.Any, 5*time.Second, ooklaStreams)
	defer client.CloseIdleConnections()

	var moved atomic.Int64
	n, err := ooklaTransfer(context.Background(), client, srv.URL+"/"+ooklaDownFile, 0, &moved)
	if err == nil {
		t.Fatalf("HTTP 404 must be an error, got %d bytes", n)
	}
	if moved.Load() != 0 {
		t.Errorf("the error page was counted as %d transferred bytes", moved.Load())
	}
}

// TestOoklaTransferCacheBusting: приём идёт с уникальным параметром, иначе
// прокси на пути отдаст файл из кеша и замерена будет не та скорость.
func TestOoklaTransferCacheBusting(t *testing.T) {
	seen := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.URL.RawQuery
		_, _ = w.Write([]byte("payload"))
	}))
	defer srv.Close()

	client := netutil.StreamClient(netutil.Any, 5*time.Second, ooklaStreams)
	defer client.CloseIdleConnections()

	var moved atomic.Int64
	for i := 0; i < 2; i++ {
		if _, err := ooklaTransfer(context.Background(), client, srv.URL+"/"+ooklaDownFile, 0, &moved); err != nil {
			t.Fatalf("ooklaTransfer: %v", err)
		}
	}
	first, second := <-seen, <-seen
	if first == "" || first == second {
		t.Errorf("two downloads used the same query %q — a cache would answer the second one", first)
	}
}

// TestMeasureWindowReportsFailure: если передавать не удалось, наружу должна
// уйти ошибка, а не убедительные «0.00 Mbps».
func TestMeasureWindowReportsFailure(t *testing.T) {
	want := errors.New("connection refused")
	_, err := measureWindow(context.Background(),
		window{streams: 2, length: time.Second, warmup: 100 * time.Millisecond, budget: 1 << 20},
		func(context.Context, *atomic.Int64) (int64, error) { return 0, want })
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

// TestMeasureWindowStopsAtBudget: потолок трафика существует ради чужих
// серверов, и превышать его нельзя даже на быстром канале.
func TestMeasureWindowStopsAtBudget(t *testing.T) {
	const budget = 8 << 20
	var moved atomic.Int64
	mbps, err := measureWindow(context.Background(),
		window{streams: 4, length: 30 * time.Second, warmup: time.Millisecond, budget: budget},
		func(_ context.Context, m *atomic.Int64) (int64, error) {
			const chunk = 1 << 20
			m.Add(chunk)
			time.Sleep(time.Millisecond)
			return chunk, nil
		})
	if err != nil {
		t.Fatalf("measureWindow: %v", err)
	}
	if mbps <= 0 {
		t.Errorf("rate = %v, want a positive number", mbps)
	}
	if got := moved.Load(); got > budget {
		t.Errorf("transferred %d bytes, over the %d-byte budget", got, budget)
	}
}
