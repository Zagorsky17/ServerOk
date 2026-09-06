package netcheck

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// speedwindow.go — общий движок обоих способов замера скорости.
//
// Мерить «сколько времени ушло на N мегабайт» нельзя: результат такого замера
// зависит не от канала, а от задержки. На плече с RTT 80 мс передача в
// несколько мегабайт целиком укладывается в разгон TCP и занижает скорость в
// разы. Поэтому замер идёт наоборот — фиксированное окно времени, а посчитано
// в нём только то, что прошло после разгона.
//
// Второе, что здесь важно, — несколько параллельных потоков. Одно
// TCP-соединение на дальнем плече упирается в окно перегрузки задолго до
// потолка канала; официальный клиент Ookla по той же причине качает в
// несколько соединений.

// transferFunc выполняет одну передачу и возвращает число прошедших байт,
// попутно прибавляя их к moved по мере движения: замер за фиксированное время
// должен видеть прогресс, а не только итог.
type transferFunc func(ctx context.Context, moved *atomic.Int64) (int64, error)

// window — параметры замера одного направления.
type window struct {
	streams int           // сколько передач идёт параллельно
	length  time.Duration // длительность окна
	warmup  time.Duration // сколько отбрасывается на разгон TCP
	budget  int64         // потолок трафика: достигнув его, замер прекращается
}

// measureWindow гоняет w.streams параллельных передач в течение w.length и
// возвращает скорость в Мбит/с.
//
// Считается не весь объём, а только тот, что прошёл после w.warmup: к этому
// моменту окно перегрузки TCP раскрыто, и цифра отражает канал, а не разгон.
// Если до конца разгона дело не дошло (медленный канал, ранний обрыв), берётся
// всё измеренное — это занижает результат, но лучше, чем пустая строка.
func measureWindow(ctx context.Context, w window, transfer transferFunc) (float64, error) {
	// Окну даётся небольшой запас: соединения обрываются по этому контексту,
	// и он же не даёт зависшему потоку задержать весь тест.
	ctx, cancel := context.WithTimeout(ctx, w.length+10*time.Second)
	defer cancel()
	deadline := time.Now().Add(w.length)

	var (
		moved     atomic.Int64
		warmBytes atomic.Int64
		warmNanos atomic.Int64
		wg        sync.WaitGroup
		mu        sync.Mutex
		first     error
	)
	// Снимок счётчика на границе разгона: вычитая его, получаем «чистый»
	// участок замера.
	timer := time.AfterFunc(w.warmup, func() {
		warmBytes.Store(moved.Load())
		warmNanos.Store(time.Now().UnixNano())
	})
	defer timer.Stop()

	perStream := w.budget / int64(w.streams)
	start := time.Now()
	for i := 0; i < w.streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var sent int64
			for time.Now().Before(deadline) && sent < perStream && ctx.Err() == nil {
				n, err := transfer(ctx, &moved)
				sent += n
				if err != nil {
					// Обрыв по концу окна — это норма, а не сбой.
					if ctx.Err() == nil && time.Now().Before(deadline) {
						mu.Lock()
						if first == nil {
							first = err
						}
						mu.Unlock()
					}
					return
				}
			}
		}()
	}
	// Потоки сами следят за deadline; отменяем контекст, как только окно
	// вышло, чтобы не ждать хвост последнего запроса.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Until(deadline)):
		cancel()
		<-done
	}

	// Таймер снимка останавливается до чтения счётчиков: иначе он мог бы
	// сработать между чтением total и warm, и разница вышла бы нулевой на
	// вполне успешном замере.
	timer.Stop()
	total, warm, warmAt := moved.Load(), warmBytes.Load(), warmNanos.Load()
	// Мегабайт — нижняя граница осмысленного замера. Меньше означает, что
	// потоки умерли почти сразу (отказ, обрыв), и делить это на время нельзя:
	// получится «0.00 Mbps» вместо честной ошибки.
	if total < 1<<20 && first != nil {
		return 0, first
	}
	bytes, elapsed := total, time.Since(start)
	if warmAt != 0 && total > warm {
		// Разгон отработал — считаем только то, что после него.
		bytes, elapsed = total-warm, time.Since(time.Unix(0, warmAt))
	}
	if bytes <= 0 || elapsed <= 0 {
		// Замер уложился в разгон целиком (быстро упёрлись в потолок трафика
		// или оборвались): считаем по всему окну — грубее, но это результат.
		bytes, elapsed = total, time.Since(start)
	}
	if bytes == 0 || elapsed <= 0 {
		if first != nil {
			return 0, first
		}
		return 0, errors.New("no data was transferred")
	}
	return float64(bytes) * 8 / elapsed.Seconds() / 1e6, nil
}
