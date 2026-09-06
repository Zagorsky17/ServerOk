package bench

// mem.go — бенчмарк памяти: пропускная способность (запись, чтение,
// копирование) и задержка случайного доступа.
//
// Размеры буферов считаются от доступной оперативной памяти. Это не
// перестраховка: инструмент рассчитан на VPS с 512 МБ-1 ГБ, где
// фиксированный буфер на сотню мегабайт уводит машину в своп, и тест меряет
// уже не память, а диск.

import (
	"context"
	"math/rand/v2"
	"runtime/debug"
	"time"

	"github.com/shirou/gopsutil/v4/mem"

	"github.com/Zagorsky17/ServerOk/internal/report"
)

const (
	maxMemBuffer = 512 << 20 // потолок буфера пропускной способности
	minMemBuffer = 64 << 20  // ниже этого замер уже нерепрезентативен
	// Массив для «погони за указателем» должен быть больше кэша последнего
	// уровня — иначе меряется кэш, а не память. При этом он ограничен долей
	// доступной памяти: на маленьком VPS фиксированные 64 МБ поверх буфера
	// пропускной способности означают своп, а не измерение.
	maxChaseBuffer = 64 << 20
	minChaseBuffer = 4 << 20
	chaseSteps     = 20_000_000
)

// Memory измеряет пропускную способность памяти и задержку доступа.
//
// Порядок важен: сначала три замера пропускной способности на одном большом
// буфере, затем буферы освобождаются, и только потом выделяется массив для
// замера задержки. Так пиковое потребление памяти остаётся ограниченным.
func Memory(ctx context.Context, status func(string, ...any)) (*report.MemBench, error) {
	available := availableRAM(ctx)

	size := uint64(maxMemBuffer)
	if available > 0 && available/4 < size {
		size = available / 4
	}
	if size < minMemBuffer {
		size = minMemBuffer
	}
	size -= size % 8

	res := &report.MemBench{BufferBytes: size}
	words := int(size / 8)

	status("memory: sequential write")
	src := make([]uint64, words)
	res.WriteGBs = best(3, func() float64 {
		start := time.Now()
		for i := range src {
			src[i] = uint64(i)
		}
		return gbps(size, time.Since(start))
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	status("memory: sequential read")
	res.ReadGBs = best(3, func() float64 {
		var sum uint64
		start := time.Now()
		for _, v := range src {
			sum += v
		}
		d := time.Since(start)
		sink = sum
		return gbps(size, d)
	})

	status("memory: copy")
	dst := make([]uint64, words)
	res.CopyGBs = best(3, func() float64 {
		start := time.Now()
		copy(dst, src)
		return gbps(size, time.Since(start))
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Освобождаем буферы пропускной способности перед выделением массива для
	// замера задержки: держать оба одновременно на маленькой машине нельзя.
	//
	// Одного обнуления ссылок мало — сборщик запустится, только когда куча
	// снова дорастёт до порога, а порог после гигабайта буферов высокий.
	// Замер это подтверждал: при буфере 512 МиБ пик достигал 1157 МБ, то есть
	// src, dst и массив задержки лежали в памяти одновременно. FreeOSMemory
	// собирает мусор и отдаёт страницы ядру, поэтому обещание выше становится
	// правдой, а не намерением.
	src, dst = nil, nil
	debug.FreeOSMemory()

	status("memory: random access latency")
	res.LatencyNs = pointerChase(chaseSize(availableRAM(ctx)))
	return res, nil
}

// availableRAM — сколько памяти можно занять, не уходя в своп.
// Это не Free, а Available: учитываются кэши, которые ядро отдаст по запросу.
func availableRAM(ctx context.Context) uint64 {
	vm, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return 0
	}
	return vm.Available
}

// chaseSize подбирает размер массива для замера задержки — не более одной
// восьмой доступной памяти и не более 64 МБ. Возвращает число слотов
// (по одному uint32 на слот).
func chaseSize(available uint64) int {
	size := uint64(maxChaseBuffer)
	if available > 0 && available/8 < size {
		size = available / 8
	}
	if size < minChaseBuffer {
		size = minChaseBuffer
	}
	return int(size / 4) // one uint32 per slot
}

// sink не даёт компилятору выбросить циклы чтения как бесполезные:
// результат обязан куда-то записываться.
var sink uint64

// gbps переводит «столько-то байт за столько-то времени» в ГБ/с.
func gbps(bytes uint64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(bytes) / (1 << 30) / d.Seconds()
}

// best берёт лучший из n прогонов. Лучший, а не средний: первый проход по
// свежевыделенному буферу оплачивает page faults, и его результат занижен.
func best(n int, f func() float64) float64 {
	out := 0.0
	for i := 0; i < n; i++ {
		if v := f(); v > out {
			out = v
		}
	}
	return out
}

// pointerChase проходит по одному длинному циклу из n слотов: каждый
// следующий адрес известен только после загрузки предыдущего значения,
// поэтому процессор не может выполнить упреждающее чтение, и мы получаем
// настоящую задержку обращения к памяти.
//
// Цикл строится алгоритмом Саттоло — его перестановка гарантированно состоит
// ровно из одного цикла. Это позволяет обойтись единственным массивом:
// rand.Perm потребовал бы второй такой же и удвоил расход памяти.
func pointerChase(n int) float64 {
	if n < 2 {
		return 0
	}
	next := make([]uint32, n)
	for i := range next {
		next[i] = uint32(i)
	}
	for i := n - 1; i > 0; i-- {
		j := rand.IntN(i) // строго меньше i — это Саттоло, а не Фишер-Йетс
		next[i], next[j] = next[j], next[i]
	}

	steps := chaseSteps
	if steps < n {
		steps = n
	}
	p := uint32(0)
	start := time.Now()
	for i := 0; i < steps; i++ {
		p = next[p]
	}
	elapsed := time.Since(start)
	sink = uint64(p)
	return float64(elapsed.Nanoseconds()) / float64(steps)
}
