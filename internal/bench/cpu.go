package bench

// cpu.go — бенчмарк процессора.
//
// Методика: четыре разнотипные нагрузки, каждая крутится фиксированное время
// (по умолчанию 2.5 с) сначала в один поток, затем во столько потоков,
// сколько логических ядер. Считается не «сколько заняло», а «сколько успели
// обработать за отведённое время» — так результат не зависит от разрешения
// таймера и не требует прогрева.
//
// Нагрузки подобраны так, чтобы задеть разные блоки процессора:
//   - AES-256-GCM   — аппаратное шифрование (AES-NI/ARM crypto);
//   - SHA-256       — хеширование, тоже с аппаратной поддержкой;
//   - gzip          — ветвления и работа с памятью, чистая ALU-нагрузка;
//   - решето простых — целочисленная арифметика и обход массива.
//
// Отдельно считается коэффициент масштабирования (многопоток/однопоток): на
// оверселленных VPS он заметно ниже числа ядер.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/report"
)

// workload — одна нагрузка. Функция work крутится, пока не выставлен флаг
// stop, и возвращает число обработанных «единиц»: байты для пропускных
// тестов, количество проверенных чисел для решета.
type workload struct {
	name     string
	unit     string
	baseline float64 // ориентир для одного ядра, по нему нормируется балл
	scale    float64 // делитель, переводящий «единицы» в единицы отчёта
	work     func(stop *atomic.Bool) float64
}

// CPU прогоняет все нагрузки в одном потоке и на всех ядрах.
//
// secs — время на одну нагрузку в каждом режиме; при -cpu-time 0.5 прогон
// становится грубее, но быстрее (удобно для проверки работоспособности).
func CPU(ctx context.Context, secs float64, status func(string, ...any)) (*report.CPUBench, error) {
	if secs <= 0 {
		secs = 2.5
	}
	threads := runtime.NumCPU()
	out := &report.CPUBench{Threads: threads}

	// baseline — примерный результат одного ядра современного серверного
	// процессора. Балл нормируется на эти числа, поэтому ≈1000 очков означает
	// «одно современное ядро», 500 — вдвое медленнее, 2000 — вдвое быстрее.
	// Это относительный индекс, а не попугаи Geekbench.
	loads := []workload{
		{"AES-256-GCM", "MB/s", 5000, 1 << 20, aesWorkload},
		{"SHA-256", "MB/s", 2000, 1 << 20, sha256Workload},
		{"Gzip (level 6)", "MB/s", 300, 1 << 20, gzipWorkload},
		{"Prime sieve", "MOps/s", 1000, 1e6, primeWorkload},
	}

	var singleRatios, multiRatios []float64
	for _, w := range loads {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		status("cpu: %s (single-thread)", w.name)
		single := measure(ctx, w, 1, secs)
		status("cpu: %s (%d threads)", w.name, threads)
		multi := measure(ctx, w, threads, secs)

		out.Workloads = append(out.Workloads, report.CPUResult{
			Name: w.name, Unit: w.unit, Single: single, Multi: multi,
		})
		singleRatios = append(singleRatios, single/w.baseline)
		multiRatios = append(multiRatios, multi/w.baseline)
	}

	out.Score.Single = geomean(singleRatios) * 1000
	out.Score.Multi = geomean(multiRatios) * 1000
	if out.Score.Single > 0 {
		out.Score.Scaling = out.Score.Multi / out.Score.Single
	}
	return out, nil
}

// measure запускает нагрузку в n горутин на secs секунд и возвращает
// суммарную производительность в единицах этой нагрузки.
//
// Горутины стартуют сразу и работают до флага stop; ограничение по времени
// даёт таймер, а отмена контекста (Ctrl+C) прерывает замер досрочно.
func measure(ctx context.Context, w workload, n int, secs float64) float64 {
	var stop atomic.Bool
	var total atomic.Uint64
	var wg sync.WaitGroup

	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			units := w.work(&stop)
			total.Add(uint64(units))
		}()
	}

	timer := time.NewTimer(time.Duration(secs * float64(time.Second)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
	// Секундомер останавливается ДО ожидания горутин: пока wg.Wait() соберёт
	// всех, пройдут ещё сотни микросекунд, и включение их в знаменатель
	// занижало бы результат.
	//
	// Обратная сторона: работу, которую горутина успевает доделать между
	// снимком времени и тем, как заметит stop, мы засчитываем, а время на неё
	// — нет. Это завышение, но оно ограничено одним проходом внутреннего
	// цикла (десятки микросекунд против секунд замера).
	elapsed := time.Since(start).Seconds()
	stop.Store(true)
	wg.Wait()

	if elapsed <= 0 {
		return 0
	}
	return float64(total.Load()) / w.scale / elapsed
}

// aesWorkload шифрует буфер AES-256-GCM. Ключ случайный, но одноразовый nonce
// не меняется: криптостойкость здесь не нужна, важна только скорость блока
// шифрования. Внутренний цикл на 16 итераций уменьшает долю проверок флага.
func aesWorkload(stop *atomic.Bool) float64 {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0
	}
	nonce := make([]byte, gcm.NonceSize())
	plain := make([]byte, 64<<10)
	dst := make([]byte, 0, len(plain)+gcm.Overhead())
	var processed float64
	for !stop.Load() {
		for i := 0; i < 16 && !stop.Load(); i++ {
			dst = gcm.Seal(dst[:0], nonce, plain, nil)
			processed += float64(len(plain))
		}
	}
	return processed
}

// sha256Workload хеширует один и тот же буфер: измеряется пропускная
// способность хеша, а не работа с памятью.
//
// Sum пишет в собственный массив, а не в nil: Sum(nil) выделял бы 32 байта
// на каждой итерации, и в счёт шла бы работа аллокатора.
func sha256Workload(stop *atomic.Bool) float64 {
	buf := make([]byte, 64<<10)
	h := sha256.New()
	var digest [sha256.Size]byte
	var processed float64
	for !stop.Load() {
		for i := 0; i < 16 && !stop.Load(); i++ {
			h.Reset()
			h.Write(buf)
			h.Sum(digest[:0])
			processed += float64(len(buf))
		}
	}
	return processed
}

// gzipWorkload сжимает текстоподобный корпус на уровне по умолчанию.
// Вывод уходит в io.Discard — интересна скорость компрессии, а не запись.
func gzipWorkload(stop *atomic.Bool) float64 {
	corpus := compressibleCorpus(256 << 10)
	var processed float64
	w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
	for !stop.Load() {
		w.Reset(io.Discard)
		if _, err := w.Write(corpus); err != nil {
			break
		}
		if err := w.Close(); err != nil {
			break
		}
		processed += float64(len(corpus))
	}
	return processed
}

// primeWorkload считает простые числа до 200 000 решетом Эратосфена.
// Единица измерения — количество проверенных чисел: массив на 200 КБ
// помещается в кэш, поэтому меряется именно арифметика, а не память.
//
// Решето выделяется ОДИН раз и очищается через clear(): выделять его на
// каждой итерации нельзя. Это не микрооптимизация — 200 КБ мусора за проход
// на каждом ядре заставляют сборщик работать непрерывно, и в многопоточном
// режиме он отъедает те самые ядра, которые мы измеряем. Замер показывал
// 4500 MOps/s против 7800 и масштабирование 2.85 вместо 4.66 на восьми
// ядрах — то есть нагрузка мерила аллокатор Go, а не процессор.
func primeWorkload(stop *atomic.Bool) float64 {
	const limit = 200000
	sieve := make([]bool, limit)
	var ops float64
	for !stop.Load() {
		clear(sieve)
		for i := 2; i*i < limit; i++ {
			if sieve[i] {
				continue
			}
			for j := i * i; j < limit; j += i {
				sieve[j] = true
			}
		}
		ops += limit
	}
	return ops
}

// compressibleCorpus готовит текстоподобные данные: на случайных байтах gzip
// почти не работает и тест выродился бы в копирование.
func compressibleCorpus(size int) []byte {
	var b bytes.Buffer
	words := []string{"server", "tester", "benchmark", "network", "latency", "throughput",
		"kernel", "virtual", "machine", "storage", "provider", "datacenter", "routing"}
	for b.Len() < size {
		for _, w := range words {
			b.WriteString(w)
			b.WriteByte(' ')
			if b.Len() >= size {
				break
			}
		}
		b.WriteByte('\n')
	}
	return b.Bytes()[:size]
}

// geomean — среднее геометрическое. Оно устойчивее среднего арифметического,
// когда величины разного порядка: одна очень быстрая нагрузка не может
// «вытянуть» общий балл.
func geomean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		if v <= 0 {
			return 0
		}
		sum += math.Log(v)
	}
	return math.Exp(sum / float64(len(vals)))
}
