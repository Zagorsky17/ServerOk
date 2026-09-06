package netcheck

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/showwin/speedtest-go/speedtest"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
	"github.com/Zagorsky17/ServerOk/internal/report"
)

// speedtest.go — измерение скорости канала через инфраструктуру speedtest.net
// (библиотека speedtest-go, чистый Go, без внешних бинарников).
//
// Главное отличие от bench.sh и его клонов: серверы ищутся по названию города,
// а не по «зашитым» числовым ID. Идентификаторы устаревают — спонсоры уходят,
// серверы отключают, и такие скрипты годами показывают «Test failed» для
// половины строк. Здесь на каждый город берётся до трёх кандидатов, заведомо
// мёртвые отсеиваются HTTP-пробой, а сервер, отдавший нулевую скорость,
// считается сломанным, и берётся следующий.

// Способ замера выбирается пользователем: у Ookla и Cloudflare разные
// сильные стороны, и подменять один другим нельзя (см. speedcf.go).
const (
	MethodOokla      = report.MethodOokla
	MethodCloudflare = report.MethodCloudflare
)

// Methods возвращает поддерживаемые способы замера — для справки по флагам и
// для меню выбора.
func Methods() []string { return []string{MethodOokla, MethodCloudflare} }

// NormalizeMethod приводит значение флага к каноническому виду и возвращает
// пустую строку, если способ неизвестен. Проверять значение нужно сразу при
// разборе флагов: узнать об опечатке через двадцать минут прогона — плохо.
func NormalizeMethod(method string) string {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "", MethodOokla, "speedtest", "speedtest.net":
		return MethodOokla
	case MethodCloudflare, "cf":
		return MethodCloudflare
	}
	return ""
}

// node — одна точка измерения.
type node struct {
	Label   string
	Search  string // ключевое слово для поиска; пусто — «ближайший сервер»
	Country string // ожидаемая страна, ею фильтруются результаты поиска
}

// Наборы точек: fast — быстрая проверка (3 точки), default — как в bench.sh
// (9 точек по миру), full — расширенный, включая Китай и Индию. Отдельно
// заданы региональные наборы: гонять все девять точек ради одного вопроса
// «как канал до Европы» долго и незачем.
//
// В региональных наборах нет пункта «ближайший сервер»: он выбирается по
// расстоянию и к запрошенному региону отношения не имеет.
var (
	fastSet = []node{
		{"Speedtest.net", "", ""},
		{"Los Angeles, US", "Los Angeles", "United States"},
		{"Amsterdam, NL", "Amsterdam", "Netherlands"},
	}
	defaultSet = []node{
		{"Speedtest.net", "", ""},
		{"Los Angeles, US", "Los Angeles", "United States"},
		{"Dallas, US", "Dallas", "United States"},
		{"Montreal, CA", "Montreal", "Canada"},
		{"Paris, FR", "Paris", "France"},
		{"Amsterdam, NL", "Amsterdam", "Netherlands"},
		{"Hong Kong", "Hong Kong", "Hong Kong"},
		{"Singapore, SG", "Singapore", "Singapore"},
		{"Tokyo, JP", "Tokyo", "Japan"},
	}
	usSet = []node{
		{"Los Angeles, US", "Los Angeles", "United States"},
		{"Seattle, US", "Seattle", "United States"},
		{"Dallas, US", "Dallas", "United States"},
		{"Chicago, US", "Chicago", "United States"},
		{"New York, US", "New York", "United States"},
		{"Miami, US", "Miami", "United States"},
	}
	euSet = []node{
		{"London, UK", "London", "United Kingdom"},
		{"Amsterdam, NL", "Amsterdam", "Netherlands"},
		{"Frankfurt, DE", "Frankfurt", "Germany"},
		{"Paris, FR", "Paris", "France"},
		{"Warsaw, PL", "Warsaw", "Poland"},
		{"Stockholm, SE", "Stockholm", "Sweden"},
	}
	asiaSet = []node{
		{"Hong Kong", "Hong Kong", "Hong Kong"},
		{"Singapore, SG", "Singapore", "Singapore"},
		{"Tokyo, JP", "Tokyo", "Japan"},
		{"Seoul, KR", "Seoul", "Korea"},
		{"Mumbai, IN", "Mumbai", "India"},
	}
	fullSet = append(append([]node{}, defaultSet...), []node{
		{"Frankfurt, DE", "Frankfurt", "Germany"},
		{"London, UK", "London", "United Kingdom"},
		{"Shanghai, CN", "Shanghai", "China"},
		{"Guangzhou, CN", "Guangzhou", "China"},
		{"Mumbai, IN", "Mumbai", "India"},
		{"Sydney, AU", "Sydney", "Australia"},
		{"Sao Paulo, BR", "Sao Paulo", "Brazil"},
	}...)
)

// nodeSets — наборы, доступные по имени во флаге -nodes. Синонимы нужны для
// удобства: «europe» и «eu» — одно и то же, промахнуться нельзя.
var nodeSets = map[string][]node{
	"fast":          fastSet,
	"default":       defaultSet,
	"full":          fullSet,
	"us":            usSet,
	"usa":           usSet,
	"america":       usSet,
	"north-america": usSet,
	"eu":            euSet,
	"europe":        euSet,
	"asia":          asiaSet,
}

// SetNames возвращает канонические имена наборов в порядке «от быстрого к
// подробному» — для справки по флагам и для меню выбора региона.
func SetNames() []string {
	return []string{"fast", "default", "full", "us", "eu", "asia"}
}

// nodeTimeout — потолок времени на одну точку, включая перебор запасных
// серверов. Произведение этого значения на число точек не должно превышать
// -test-timeout, иначе тест оборвётся на середине.
const nodeTimeout = 90 * time.Second

// Speedtest измеряет отдачу, приём и задержку выбранным способом: method —
// ookla или cloudflare, set — набор точек (для Cloudflare не применяется,
// туда всегда идёт ближайший edge-узел).
//
// onResult вызывается после каждой точки — благодаря этому строки таблицы
// появляются на экране по мере измерения, а не спустя минуты молчания.
// Если время вышло, возвращается уже измеренное: частичная таблица полезнее
// пустой.
func Speedtest(ctx context.Context, method, set string, onResult func(report.SpeedNode), status func(string, ...any)) (*report.Speedtest, error) {
	switch NormalizeMethod(method) {
	case MethodOokla:
		return ooklaSpeedtest(ctx, set, onResult, status)
	case MethodCloudflare:
		return cloudflareSpeedtest(ctx, onResult, status)
	}
	return nil, fmt.Errorf("unknown speedtest method %q (want one of %s)", method, strings.Join(Methods(), ", "))
}

// ooklaSpeedtest — замер по набору городов через инфраструктуру speedtest.net.
func ooklaSpeedtest(ctx context.Context, set string, onResult func(report.SpeedNode), status func(string, ...any)) (*report.Speedtest, error) {
	nodes, err := resolveSet(set)
	if err != nil {
		return nil, err
	}

	status("speedtest: locating the nearest server")
	base := speedtest.New()
	// Сведения о пользователе нужны только для расстояния. speedtest.net
	// нередко ограничивает этот запрос по частоте, но список серверов при этом
	// продолжает работать, поэтому ошибка не фатальна.
	_, _ = base.FetchUserInfoContext(ctx)

	out := &report.Speedtest{Method: MethodOokla, Set: strings.ToLower(strings.TrimSpace(set))}
	for _, n := range nodes {
		if ctx.Err() != nil {
			// Время вышло: отдаём уже измеренные строки, а не теряем весь тест.
			return out, nil
		}
		status("speedtest: %s", n.Label)
		out.Nodes = append(out.Nodes, measureNode(ctx, base, n))
		if onResult != nil {
			onResult(out.Nodes[len(out.Nodes)-1])
		}
	}
	if len(out.Nodes) == 0 {
		return nil, errors.New("no speedtest nodes were measured")
	}
	return out, nil
}

// measureNode измеряет одну точку: задержка, отдача, приём — в этом порядке.
// Задержка первой: она дешёвая и сразу отсеивает нерабочий сервер.
func measureNode(ctx context.Context, base *speedtest.Speedtest, n node) report.SpeedNode {
	row := report.SpeedNode{Name: n.Label}
	ctx, cancel := context.WithTimeout(ctx, nodeTimeout)
	defer cancel()

	client, candidates, err := pickServers(ctx, base, n)
	if err != nil {
		row.Failed, row.Err = true, report.Truncate(err.Error(), 60)
		return row
	}
	defer client.Manager.Reset()

	// Перебираем кандидатов: если сервер не отвечает или отдаёт мусор, пробуем
	// следующий в том же городе, и только исчерпав всех, помечаем точку как
	// неудачную.
	var lastErr error
	for _, srv := range candidates {
		if ctx.Err() != nil {
			break
		}
		if err := srv.PingTestContext(ctx, nil); err != nil {
			lastErr = err
			continue
		}
		res := report.SpeedNode{Name: n.Label, Sponsor: srv.Sponsor, ID: srv.ID}
		if n.Search == "" {
			res.Name = report.Truncate(report.JoinNonEmpty(" · ", n.Label, srv.Name), 18)
		}
		res.LatencyMs = float64(srv.Latency.Microseconds()) / 1000

		if err := srv.UploadTestContext(ctx); err != nil {
			lastErr = err
			client.Manager.Reset()
			continue
		}
		res.UploadMbps = srv.ULSpeed.Mbps()

		if err := srv.DownloadTestContext(ctx); err != nil {
			lastErr = err
			client.Manager.Reset()
			continue
		}
		res.DownMbps = srv.DLSpeed.Mbps()

		// Сервер ответил, но не передал ничего — это поломка, а не медленный
		// канал; такой результат в отчёт пускать нельзя.
		if res.UploadMbps <= 0 || res.DownMbps <= 0 {
			lastErr = errors.New("server reported zero throughput")
			client.Manager.Reset()
			continue
		}
		return res
	}

	row.Failed = true
	if lastErr != nil {
		row.Err = report.Truncate(lastErr.Error(), 60)
	} else {
		row.Err = "no usable server"
	}
	return row
}

// pickServers подбирает до трёх кандидатов для точки: ближайший сервер,
// совпадение по названию города или конкретный ID, если он задан явно.
func pickServers(ctx context.Context, base *speedtest.Speedtest, n node) (*speedtest.Speedtest, []*speedtest.Server, error) {
	if n.Search == "" {
		servers, err := fetchServerList(ctx, base)
		if err != nil {
			return nil, nil, err
		}
		targets, err := servers.FindServer(nil)
		if err != nil || len(targets) == 0 {
			return nil, nil, errors.New("no nearby server")
		}
		alive := reachable(ctx, limit(targets, 6), 2)
		if len(alive) == 0 {
			return nil, nil, errors.New("no reachable nearby server")
		}
		return base, alive, nil
	}
	if isServerID(n.Search) {
		srv, err := base.FetchServerByIDContext(ctx, n.Search)
		if err != nil {
			return nil, nil, fmt.Errorf("server %s unavailable", n.Search)
		}
		return base, []*speedtest.Server{srv}, nil
	}

	client := speedtest.New()
	client.NewUserConfig(&speedtest.UserConfig{Keyword: n.Search})
	servers, err := fetchServerList(ctx, client)
	if err != nil {
		return nil, nil, err
	}
	matched := reachable(ctx, matchServers(servers, n), 3)
	if len(matched) == 0 {
		return nil, nil, fmt.Errorf("no reachable server near %s", n.Label)
	}
	for _, s := range matched {
		s.Context = client
	}
	return client, matched, nil
}

// Список серверов запрашивается один раз на город, и при наборе из шести
// городов эти запросы идут почти подряд. speedtest.net на такой темп отвечает
// HTML-страницей вместо JSON, и половина точек падала с бессмысленным
// «invalid character '<'». Поэтому запросы списка сериализованы, разнесены во
// времени и повторяются с возрастающей паузой.
var (
	listMu   sync.Mutex
	lastList time.Time
)

const listGap = 2 * time.Second

// fetchServerList запрашивает список серверов, соблюдая паузу между
// запросами и повторяя попытку, если speedtest.net ответил не JSON.
func fetchServerList(ctx context.Context, c *speedtest.Speedtest) (speedtest.Servers, error) {
	listMu.Lock()
	defer listMu.Unlock()

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		delay := time.Until(lastList.Add(listGap))
		if attempt > 0 {
			delay = time.Duration(attempt) * 3 * time.Second
		}
		if delay > 0 {
			t := time.NewTimer(delay)
			select {
			case <-t.C:
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			}
		}
		servers, err := c.FetchServerListContext(ctx)
		lastList = time.Now()
		if err == nil {
			return servers, nil
		}
		lastErr = err
	}
	// Разбор HTML как JSON — это и есть отказ по частоте запросов; писать в
	// отчёт «invalid character» бессмысленно.
	if strings.Contains(lastErr.Error(), "invalid character") {
		return nil, errors.New("speedtest.net rate-limited the server list")
	}
	return nil, lastErr
}

// matchServers ранжирует найденное: сначала серверы в нужном городе, затем в
// нужной стране, затем всё остальное, что вернул поиск.
func matchServers(servers speedtest.Servers, n node) []*speedtest.Server {
	city := strings.ToLower(n.Search)
	country := strings.ToLower(n.Country)
	var inCity, inCountry, others []*speedtest.Server
	for _, s := range servers {
		sc := strings.ToLower(s.Country)
		switch {
		case country != "" && !strings.Contains(sc, country):
			others = append(others, s)
		case strings.Contains(strings.ToLower(s.Name), city):
			inCity = append(inCity, s)
		default:
			inCountry = append(inCountry, s)
		}
	}
	return limit(append(append(inCity, inCountry...), others...), 8)
}

// reachable оставляет первые want серверов, чей HTTP-эндпоинт отвечает.
//
// Проверка именно HTTP, а не TCP: у мёртвых спонсоров порт нередко открыт
// (соединение устанавливается), но приложение молчит — такой сервер съедал бы
// всё время, отведённое на точку. Любой код ответа считается признаком жизни,
// включая 404 и 500: у разных сборок Ookla разное поведение на GET.
func reachable(ctx context.Context, candidates []*speedtest.Server, want int) []*speedtest.Server {
	type probe struct {
		idx int
		ok  bool
	}
	// Своя отмена — ради раннего выхода ниже: недоделанные пробы нужно
	// прекратить, а не бросить висеть до конца их таймаута.
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Буфер на всех: горутина, чей результат уже не нужен, должна суметь
	// отправить его и завершиться, а не залипнуть на отправке навсегда.
	results := make(chan probe, len(candidates))
	for i, s := range candidates {
		go func(i int, host string) {
			client := netutil.Client(netutil.Any, 5*time.Second)
			defer client.CloseIdleConnections()
			// Любой ответ означает, что демон speedtest жив.
			_, err := netutil.Get(pctx, client, "http://"+host+"/speedtest/upload.php", 4<<10, nil)
			results <- probe{i, err == nil}
		}(i, s.Host)
	}

	picker := newPrefixPicker(len(candidates), want)
	for pending := len(candidates); pending > 0 && !picker.full(); pending-- {
		p := <-results
		picker.mark(p.idx, p.ok)
	}
	var out []*speedtest.Server
	for _, i := range picker.chosen {
		out = append(out, candidates[i])
	}
	return out
}

// prefixPicker набирает первых want живых кандидатов, сохраняя их исходный
// порядок: он же порядок приоритета (сначала серверы нужного города, потом
// страны, потом всё остальное), поэтому «первый ответивший» и «лучший» — не
// одно и то же, и брать кандидатов в порядке прихода проб нельзя.
//
// Отсюда же берётся ранний выход. Решение про кандидата принимается, как
// только известен весь префикс до него, поэтому набрать want удаётся обычно
// задолго до того, как ответят все пробы. Ждать остальных незачем: мёртвый
// спонсор держит соединение все пять секунд таймаута, и на наборе из шести
// городов это полминуты пустого ожидания.
type prefixPicker struct {
	state  []int8 // 0 — ещё неизвестно, 1 — отвечает, -1 — молчит
	next   int    // граница разобранного префикса
	want   int
	chosen []int // индексы выбранных кандидатов, в исходном порядке
}

func newPrefixPicker(n, want int) *prefixPicker {
	return &prefixPicker{state: make([]int8, n), want: want}
}

// mark учитывает результат одной пробы и продвигает границу префикса
// настолько, насколько позволяет уже известное.
func (p *prefixPicker) mark(idx int, alive bool) {
	if alive {
		p.state[idx] = 1
	} else {
		p.state[idx] = -1
	}
	for p.next < len(p.state) && p.state[p.next] != 0 && !p.full() {
		if p.state[p.next] == 1 {
			p.chosen = append(p.chosen, p.next)
		}
		p.next++
	}
}

// full сообщает, что нужное количество набрано и оставшиеся пробы не важны.
func (p *prefixPicker) full() bool { return len(p.chosen) >= p.want }

// limit обрезает список кандидатов.
func limit(in []*speedtest.Server, n int) []*speedtest.Server {
	if len(in) > n {
		return in[:n]
	}
	return in
}

// isServerID отличает числовой идентификатор сервера от названия города.
func isServerID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ValidateSet проверяет значение флага -nodes, ничего не измеряя, — чтобы
// опечатка вскрылась при разборе флагов, а не в середине прогона.
func ValidateSet(set string) error {
	_, err := resolveSet(set)
	return err
}

// resolveSet превращает значение флага -nodes в список точек. Значение —
// перечисленные через запятую имена наборов (fast/default/full/us/eu/asia) и
// числовые ID серверов speedtest.net; их можно смешивать, например
// «eu,asia» или «us,12345».
//
// Повторы отбрасываются: «eu,europe» или пересекающиеся наборы не должны
// приводить к тому, что один и тот же город меряется дважды.
func resolveSet(set string) ([]node, error) {
	set = strings.TrimSpace(set)
	if set == "" {
		set = "default"
	}
	var out []node
	seen := map[string]bool{}
	add := func(n node) {
		key := n.Label + "|" + n.Search
		if !seen[key] {
			seen[key] = true
			out = append(out, n)
		}
	}
	for _, part := range strings.Split(set, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if nodes, ok := nodeSets[strings.ToLower(part)]; ok {
			for _, n := range nodes {
				add(n)
			}
			continue
		}
		if isServerID(part) {
			add(node{Label: "Server " + part, Search: part})
			continue
		}
		return nil, fmt.Errorf("unknown speedtest node set %q (want one of %s, or a server ID)",
			part, strings.Join(SetNames(), ", "))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("unknown speedtest node set %q", set)
	}
	return out, nil
}
