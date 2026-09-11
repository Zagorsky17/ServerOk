// Пакет report — единая модель данных отчёта и три способа её показать.
//
// Договорённость проекта: тесты ничего не печатают, а заполняют структуру
// Report. Дальше её рендерят:
//   - text.go     — цветной вывод в терминал (та самая рамка bench.sh);
//   - json.go     — машинный формат для cron и дашбордов (-json);
//   - markdown.go — таблицы для форумов и тикетов (-md).
//
// Благодаря этому все три формата всегда согласованы: новое поле достаточно
// добавить в модель и в нужные рендеры, а тест править не приходится.
//
// Файлы пакета: model.go (структуры), format.go (форматирование величин),
// text.go / json.go / markdown.go (рендеры).
package report

import (
	"sync"
	"time"
)

// Report — весь результат прогона. Указатели на блоки равны nil, если
// соответствующий тест не запускался: так в JSON не попадают пустые секции
// (все поля помечены omitempty).
type Report struct {
	// mu защищает Failures: подтесты, работающие параллельно (RDAP внутри
	// теста IP, проверки сервисов), могут добавлять записи одновременно.
	mu sync.Mutex

	Version   string    `json:"version"`            // версия бинарника (-ldflags при сборке)
	Generated time.Time `json:"generated_at"`       // момент запуска
	Duration  string    `json:"duration,omitempty"` // сколько занял прогон целиком
	Tests     []string  `json:"tests_run"`          // какие тесты фактически выполнялись

	System    *System     `json:"system,omitempty"`
	CPU       *CPUBench   `json:"cpu_benchmark,omitempty"`
	Memory    *MemBench   `json:"memory_benchmark,omitempty"`
	Disk      *DiskIO     `json:"disk_io,omitempty"`
	Speedtest *Speedtest  `json:"speedtest,omitempty"`
	IP        *IPInfo     `json:"ip_info,omitempty"`
	Blacklist *Blacklist  `json:"blacklist,omitempty"`
	Unblock   *Unblock    `json:"unblock,omitempty"`
	Blocking  *Blocking   `json:"blocking,omitempty"`
	Network   *NetDiag    `json:"network,omitempty"`
	Domain    *DomainInfo `json:"domain,omitempty"`

	Failures []Failure `json:"failures,omitempty"`
}

// Failure — тест, который не довёл работу до конца. Попадает и в секцию
// Notes текстового отчёта, и в JSON: молча терять неудачу нельзя.
type Failure struct {
	Test   string `json:"test"`
	Reason string `json:"reason"`
}

// Lock и Unlock открыты наружу для подтестов, которым нужно защитить свою
// запись в отчёт.
func (r *Report) Lock()   { r.mu.Lock() }
func (r *Report) Unlock() { r.mu.Unlock() }

// AddFailure добавляет запись о неудаче. Потокобезопасна.
func (r *Report) AddFailure(test, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Failures = append(r.Failures, Failure{Test: test, Reason: reason})
}

// System — шапка отчёта: железо, ОС и сетевая «личность» сервера.
// Заполняется пакетом sysinfo; последние три поля (Org/Location/Region)
// приходят из геолокации, чтобы не делать второй запрос в тесте IP.
type System struct {
	CPUModel   string  `json:"cpu_model"`
	CPUCores   int     `json:"cpu_cores"`
	CPUFreqMHz float64 `json:"cpu_freq_mhz,omitempty"`
	CPUCache   string  `json:"cpu_cache,omitempty"`
	AESNI      bool    `json:"aes_ni"`
	VirtExt    bool    `json:"virt_extensions"`

	DiskTotal uint64 `json:"disk_total_bytes"`
	DiskUsed  uint64 `json:"disk_used_bytes"`
	RAMTotal  uint64 `json:"ram_total_bytes"`
	RAMUsed   uint64 `json:"ram_used_bytes"`
	SwapTotal uint64 `json:"swap_total_bytes"`
	SwapUsed  uint64 `json:"swap_used_bytes"`

	UptimeSec uint64     `json:"uptime_seconds"`
	LoadAvg   [3]float64 `json:"load_average"`

	OS             string `json:"os"`
	Arch           string `json:"arch"`
	ArchBits       string `json:"arch_bits,omitempty"`
	Kernel         string `json:"kernel"`
	TCPCongestion  string `json:"tcp_congestion_control,omitempty"`
	Virtualization string `json:"virtualization,omitempty"`

	IPv4Online bool   `json:"ipv4_online"`
	IPv6Online bool   `json:"ipv6_online"`
	Org        string `json:"organization,omitempty"`
	Location   string `json:"location,omitempty"`
	Region     string `json:"region,omitempty"`
}

// CPUBench — результат бенчмарка процессора: четыре нагрузки, каждая в
// однопоточном и многопоточном режиме, плюс сводный балл.
type CPUBench struct {
	Threads   int          `json:"threads"`
	Workloads []CPUResult  `json:"workloads"`
	Score     CPUScorePair `json:"score"`
}

// CPUResult — одна нагрузка, измеренная в обоих режимах (единица измерения
// своя у каждой: MB/s для шифрования и сжатия, MOps/s для решета).
type CPUResult struct {
	Name   string  `json:"name"`
	Unit   string  `json:"unit"`
	Single float64 `json:"single_thread"`
	Multi  float64 `json:"multi_thread"`
}

// CPUScorePair — сводный балл. Это относительный индекс: среднее
// геометрическое результатов, нормированных на базовую линию (≈1000 — одно
// современное серверное ядро). Scaling = многопоток/однопоток, показывает,
// насколько честно хостер отдаёт ядра.
type CPUScorePair struct {
	Single  float64 `json:"single_thread"`
	Multi   float64 `json:"multi_thread"`
	Scaling float64 `json:"scaling"`
}

// MemBench — пропускная способность памяти и задержка случайного доступа.
type MemBench struct {
	BufferBytes uint64  `json:"buffer_bytes"`
	WriteGBs    float64 `json:"write_gbs"`
	ReadGBs     float64 `json:"read_gbs"`
	CopyGBs     float64 `json:"copy_gbs"`
	LatencyNs   float64 `json:"random_access_latency_ns"`
}

// DiskIO — результаты дисковых замеров: три последовательные записи (как в
// bench.sh), их среднее и, если получилось измерить, 4K random write IOPS.
type DiskIO struct {
	Path        string    `json:"path"`
	BlockSize   uint64    `json:"block_size_bytes"`
	TestSize    uint64    `json:"test_size_bytes"`
	Runs        []float64 `json:"runs_mbs"`
	Average     float64   `json:"average_mbs"`
	RandWrIOPS  float64   `json:"random_write_iops,omitempty"`
	ReducedSize bool      `json:"reduced_size,omitempty"`
}

// Способы замера скорости. Значения попадают в JSON, поэтому они
// зафиксированы здесь, рядом с моделью, а не в netcheck.
const (
	MethodOokla      = "ookla"      // серверы speedtest.net по городам
	MethodCloudflare = "cloudflare" // ближайший edge-узел Cloudflare
)

// Speedtest — по строке на каждый измеренный узел. Method и Set говорят,
// чем и по какому набору точек мерили: без этого две таблицы с разными
// цифрами невозможно сравнивать.
type Speedtest struct {
	Method string      `json:"method,omitempty"`
	Set    string      `json:"node_set,omitempty"`
	Nodes  []SpeedNode `json:"nodes"`
}

// SpeedNode — результат по одному узлу. Failed=true означает, что ни один
// из живых серверов города не отдал корректных цифр; причина — в Err.
type SpeedNode struct {
	Name       string  `json:"name"`
	Sponsor    string  `json:"sponsor,omitempty"`
	ID         string  `json:"id,omitempty"`
	UploadMbps float64 `json:"upload_mbps"`
	DownMbps   float64 `json:"download_mbps"`
	LatencyMs  float64 `json:"latency_ms"`
	Failed     bool    `json:"failed"`
	Err        string  `json:"error,omitempty"`
}

// IPInfo — блок «чей это адрес»: геолокация по обеим версиям IP плюс
// регистрационная запись RDAP (владелец сети и abuse-контакт).
type IPInfo struct {
	IPv4 *Geo  `json:"ipv4,omitempty"`
	IPv6 *Geo  `json:"ipv6,omitempty"`
	RDAP *RDAP `json:"rdap,omitempty"`
}

// Geo — данные геолокации для одной версии IP. Source говорит, какой
// провайдер ответил (их три, с откатом по очереди).
type Geo struct {
	IP          string  `json:"ip"`
	ASN         string  `json:"asn,omitempty"`
	ASName      string  `json:"as_name,omitempty"`
	Org         string  `json:"organization,omitempty"`
	ISP         string  `json:"isp,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Timezone    string  `json:"timezone,omitempty"`
	Lat         float64 `json:"latitude,omitempty"`
	Lon         float64 `json:"longitude,omitempty"`
	Hosting     bool    `json:"hosting,omitempty"`
	Proxy       bool    `json:"proxy,omitempty"`
	Mobile      bool    `json:"mobile,omitempty"`
	Source      string  `json:"source,omitempty"`
}

// RDAP — регистрационная запись адреса: на кого выделена сеть, каким
// реестром, когда и куда жаловаться. Именно ради этого блока в проекте есть
// клиент RDAP вместо вызова системного whois.
type RDAP struct {
	Query      string       `json:"query"`
	Handle     string       `json:"handle,omitempty"`
	Name       string       `json:"name,omitempty"`
	StartIP    string       `json:"start_address,omitempty"`
	EndIP      string       `json:"end_address,omitempty"`
	CIDR       []string     `json:"cidr,omitempty"`
	Type       string       `json:"type,omitempty"`
	Country    string       `json:"country,omitempty"`
	Registry   string       `json:"registry,omitempty"`
	Registered string       `json:"registered,omitempty"`
	Updated    string       `json:"updated,omitempty"`
	Entities   []RDAPEntity `json:"entities,omitempty"`
	Abuse      *RDAPContact `json:"abuse_contact,omitempty"`
	Remarks    []string     `json:"remarks,omitempty"`
	Source     string       `json:"source,omitempty"`
}

// RDAPEntity — организация или контакт, привязанные к записи (владелец,
// администратор, техконтакт). Объекты-maintainer'ы отфильтровываются.
type RDAPEntity struct {
	Handle  string   `json:"handle,omitempty"`
	Name    string   `json:"name,omitempty"`
	Roles   []string `json:"roles,omitempty"`
	Country string   `json:"country,omitempty"`
}

// RDAPContact — контакт для жалоб (роль abuse), вытащенный из vCard.
type RDAPContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

// Blacklist — результат опроса чёрных списков. Checked — сколько зон
// опрошено, ListedCount — в скольких адрес найден.
type Blacklist struct {
	IP          string          `json:"ip"`
	Resolver    string          `json:"resolver,omitempty"`
	Checked     int             `json:"checked"`
	ListedCount int             `json:"listed_count"`
	Entries     []BlacklistZone `json:"entries"`
}

// BlacklistZone — вердикт одной зоны. Status: clean | listed | unavailable
// (зона отказала публичному резолверу) | error.
type BlacklistZone struct {
	Zone   string `json:"zone"`
	Status string `json:"status"` // clean | listed | unavailable | error
	Code   string `json:"code,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Unblock — доступность стриминговых и AI-сервисов с этого адреса.
type Unblock struct {
	Items []UnblockItem `json:"items"`
}

// UnblockItem — вердикт по одному сервису. Status: yes | no | restricted |
// unknown (сервис отвечает, но регион подтвердить нечем) | failed.
type UnblockItem struct {
	Service string `json:"service"`
	Status  string `json:"status"` // yes | no | restricted | failed
	Detail  string `json:"detail,omitempty"`
	Region  string `json:"region,omitempty"`
}

// Blocking — не заблокированы ли мессенджеры и соцсети на сетевом уровне:
// провайдером или страной, где стоит сервер.
type Blocking struct {
	Services []BlockService `json:"services"`
}

// BlockService — вердикт по сервису, сведённый из проверок его адресов.
// Status: ok | blocked | throttled | partial (часть адресов доступна) | failed.
type BlockService struct {
	Name   string       `json:"name"`
	Status string       `json:"status"`
	Probes []BlockProbe `json:"endpoints"`
}

// BlockProbe — проверка одного адреса. Stage — ступень, на которой соединение
// сломалось (dns | tcp | tls | http): по ней видно, чем именно режут —
// подменой DNS, по IP или по имени в SNI.
type BlockProbe struct {
	Host   string  `json:"host"`
	IP     string  `json:"ip,omitempty"`
	Status string  `json:"status"` // ok | blocked | throttled | failed
	Stage  string  `json:"stage,omitempty"`
	Detail string  `json:"detail,omitempty"`
	RTTMs  float64 `json:"connect_ms,omitempty"`
	HTTP   int     `json:"http_status,omitempty"`
	KBps   float64 `json:"throughput_kib_s,omitempty"`
}

// NetDiag — сетевая диагностика: задержки до якорей, исходящие порты,
// возможности стека и трассировки.
type NetDiag struct {
	Latency []LatencyResult `json:"latency,omitempty"`
	Ports   []PortResult    `json:"ports,omitempty"`
	Stack   *StackInfo      `json:"stack,omitempty"`
	Traces  []Trace         `json:"traceroutes,omitempty"`
}

// LatencyResult — задержка до одного якоря. Method фиксирует, чем реально
// померили (icmp, icmp-raw или tcp:443), — без этого цифры несопоставимы.
type LatencyResult struct {
	Name   string  `json:"name"`
	Host   string  `json:"host"`
	RTTMs  float64 `json:"rtt_ms"`
	LossPc float64 `json:"loss_percent"`
	Method string  `json:"method"`
	Err    string  `json:"error,omitempty"`
}

// PortResult — доступен ли исходящий TCP-порт. Главный практический смысл:
// режет ли хостер SMTP (25/465/587).
type PortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Host    string `json:"host"`
	Open    bool   `json:"open"`
	Err     string `json:"error,omitempty"`
}

// StackInfo — возможности сетевого стека: версии IP, MTU, алгоритмы
// управления перегрузкой (наличие BBR) и то, каким резолвером мы ходим.
type StackInfo struct {
	IPv4       bool     `json:"ipv4"`
	IPv6       bool     `json:"ipv6"`
	MTU        int      `json:"path_mtu,omitempty"`
	CCCurrent  string   `json:"congestion_control,omitempty"`
	CCAvail    []string `json:"congestion_control_available,omitempty"`
	BBR        bool     `json:"bbr_available"`
	Resolvers  []string `json:"resolvers,omitempty"`
	ResolverIP string   `json:"public_resolver_ip,omitempty"`
	ResolverCC string   `json:"public_resolver_country,omitempty"`
}

// Trace — трассировка до одной цели. Note объясняет, почему хопов нет или
// откуда они получены (системный traceroute, отсутствие root, фильтрация ICMP).
type Trace struct {
	Target string     `json:"target"`
	Host   string     `json:"host"`
	Hops   []TraceHop `json:"hops"`
	Note   string     `json:"note,omitempty"`
}

// TraceHop — один хоп: адрес, задержка и автономная система (ASN/Org),
// определённая через DNS-интерфейс Team Cymru.
type TraceHop struct {
	N     int     `json:"n"`
	IP    string  `json:"ip,omitempty"`
	Host  string  `json:"host,omitempty"`
	ASN   string  `json:"asn,omitempty"`
	Org   string  `json:"org,omitempty"`
	RTTMs float64 `json:"rtt_ms,omitempty"`
}

// DomainInfo — всё, что известно о домене: регистрационная запись (кто
// регистратор, когда домен создан, когда истекает, какие NS делегированы) и
// то, что домен отвечает в DNS прямо сейчас. Заполняется пакетом whois.
//
// Available=true означает, что домен свободен: тогда остальные поля пусты, и
// это не ошибка, а ответ.
type DomainInfo struct {
	Domain      string          `json:"domain"`
	Unicode     string          `json:"unicode_name,omitempty"` // исходное написание IDN-домена
	Available   bool            `json:"available,omitempty"`
	Registrar   *Registrar      `json:"registrar,omitempty"`
	Registered  string          `json:"registered,omitempty"`
	Updated     string          `json:"updated,omitempty"`
	Expires     string          `json:"expires,omitempty"`
	ExpiresDays int             `json:"expires_in_days,omitempty"` // отрицательное — домен просрочен
	Status      []string        `json:"status,omitempty"`          // коды EPP: clientTransferProhibited и прочие
	NameServers []string        `json:"name_servers,omitempty"`
	DNSSEC      string          `json:"dnssec,omitempty"`
	Contacts    []DomainContact `json:"contacts,omitempty"`
	DNS         *DomainDNS      `json:"dns,omitempty"`
	Sources     []string        `json:"sources,omitempty"`    // whois.com и/или опрошенные серверы WHOIS
	Raw         string          `json:"raw_record,omitempty"` // ответ реестра как есть
	Notes       []string        `json:"notes,omitempty"`      // источники, которые не ответили
}

// Registrar — регистратор домена и его контакт для жалоб. AbuseEmail — то
// единственное поле, ради которого запись чаще всего и запрашивают.
type Registrar struct {
	Name        string `json:"name,omitempty"`
	IANAID      string `json:"iana_id,omitempty"`
	URL         string `json:"url,omitempty"`
	WhoisServer string `json:"whois_server,omitempty"`
	AbuseEmail  string `json:"abuse_email,omitempty"`
	AbusePhone  string `json:"abuse_phone,omitempty"`
}

// DomainContact — участник записи. Role: registrant | admin | tech | billing.
// Со времён GDPR у большинства gTLD заполнены только Country и Org, поэтому
// пустые поля здесь — норма, а не признак сбоя.
type DomainContact struct {
	Role  string `json:"role"`
	Name  string `json:"name,omitempty"`
	Org   string `json:"organization,omitempty"`
	Email string `json:"email,omitempty"`
	// Web — веб-форма для связи. С введением GDPR регистраторы всё чаще
	// подставляют вместо адреса почты ссылку на форму, и без отдельного поля
	// она попадала бы в Email, где выглядела бы как рабочий адрес.
	Web      string `json:"contact_form,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Country  string `json:"country,omitempty"`
	Location string `json:"location,omitempty"`
}

// DomainDNS — ответы DNS по домену на момент прогона. Err объясняет, почему
// записей нет (NXDOMAIN, таймаут резолвера), — без этого пустой блок нельзя
// отличить от неудачи.
type DomainDNS struct {
	A       []string `json:"a,omitempty"`
	AAAA    []string `json:"aaaa,omitempty"`
	NS      []string `json:"ns,omitempty"`
	MX      []string `json:"mx,omitempty"`
	TXT     []string `json:"txt,omitempty"`
	TXTMore int      `json:"txt_omitted,omitempty"`
	CNAME   string   `json:"cname,omitempty"`
	Err     string   `json:"error,omitempty"`
}
