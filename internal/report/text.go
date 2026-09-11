package report

// text.go — рендер отчёта в терминал. Каждая функция Print* печатает одну
// секцию и вызывается из runner после успешного выполнения соответствующего
// теста (см. поле Print в реестре cmd/serverok/tests.go).
//
// Здесь нет ни одного сетевого или системного вызова: на вход приходят уже
// собранные структуры из model.go. Благодаря этому вывод легко проверять и
// он гарантированно совпадает с содержимым JSON/Markdown.

import (
	"fmt"
	"strings"

	"github.com/Zagorsky17/ServerOk/internal/ui"
)

// Banner печатает шапку с версией и подсказкой по запуску — как в bench.sh.
func Banner(version, usage string) {
	ui.Header("ServerOk — VPS Benchmark & Diagnostics")
	ui.KV(" Version", version)
	ui.KV(" Usage", usage)
	ui.Divider()
}

// PrintSystem печатает блок «железо и ОС» — тот самый экран, ради которого
// обычно и запускают такие скрипты. Поля, которых нет на текущей платформе
// (кэш CPU на macOS, congestion control вне Linux), просто пропускаются.
func PrintSystem(s *System) {
	ui.KV("CPU Model", s.CPUModel)
	cores := fmt.Sprintf("%d", s.CPUCores)
	if s.CPUFreqMHz > 0 {
		cores = fmt.Sprintf("%d @ %.3f MHz", s.CPUCores, s.CPUFreqMHz)
	}
	ui.KV("CPU Cores", cores)
	if s.CPUCache != "" {
		ui.KV("CPU Cache", s.CPUCache)
	}
	ui.KVRaw("AES-NI", enabled(s.AESNI))
	ui.KVRaw("VM-x/AMD-V", enabled(s.VirtExt))
	ui.KV("Total Disk", UsedOf(s.DiskTotal, s.DiskUsed))
	ui.KV("Total RAM", UsedOf(s.RAMTotal, s.RAMUsed))
	ui.KV("Total Swap", UsedOf(s.SwapTotal, s.SwapUsed))
	ui.KV("System Uptime", Uptime(s.UptimeSec))
	ui.KV("Load Average", fmt.Sprintf("%.2f, %.2f, %.2f", s.LoadAvg[0], s.LoadAvg[1], s.LoadAvg[2]))
	ui.KV("OS", s.OS)
	ui.KV("Arch", JoinNonEmpty(" ", s.Arch, s.ArchBits))
	ui.KV("Kernel", s.Kernel)
	if s.TCPCongestion != "" {
		ui.KV("TCP Congestion Ctrl", s.TCPCongestion)
	}
	if s.Virtualization != "" {
		ui.KV("Virtualization", s.Virtualization)
	}
	ui.KVRaw("IPv4/IPv6", onlineOffline(s.IPv4Online)+" / "+onlineOffline(s.IPv6Online))
	if s.Org != "" {
		ui.KV("Organization", s.Org)
	}
	if s.Location != "" {
		ui.KV("Location", s.Location)
	}
	if s.Region != "" {
		ui.KV("Region", s.Region)
	}
}

func enabled(b bool) string {
	if b {
		return ui.Yes("Enabled")
	}
	return ui.No("Disabled")
}

func onlineOffline(b bool) string {
	if b {
		return ui.Yes("Online")
	}
	return ui.No("Offline")
}

// PrintDisk печатает результаты дисковых замеров: три прогона, среднее и
// IOPS. Если размер теста был уменьшен из-за нехватки места, об этом
// печатается пометка — иначе цифры нельзя сравнивать с чужими.
func PrintDisk(d *DiskIO) {
	for i, r := range d.Runs {
		ui.KV(fmt.Sprintf("I/O Speed(%s run)", ordinal(i+1)), MBs(r))
	}
	ui.KV("I/O Speed(average)", MBs(d.Average))
	if d.RandWrIOPS > 0 {
		ui.KV("4K Rand Write", fmt.Sprintf("%.0f IOPS", d.RandWrIOPS))
	}
	if d.ReducedSize {
		ui.Note(fmt.Sprintf("test size reduced to %s (low free space on %s)", HumanBytes(d.TestSize), d.Path))
	}
}

func ordinal(n int) string {
	switch n {
	case 1:
		return "1st"
	case 2:
		return "2nd"
	case 3:
		return "3rd"
	default:
		return fmt.Sprintf("%dth", n)
	}
}

// PrintCPU печатает таблицу нагрузок и сводный балл.
// Ширины колонок подобраны под самые длинные значения; при их изменении
// сверяйтесь с ui.Row — выравнивание считается по видимым символам.
func PrintCPU(c *CPUBench) {
	w := []int{24, 22, 22}
	ui.Row(w, ui.Bold("Workload"), ui.Bold("Single-Thread"), ui.Bold("Multi-Thread"))
	for _, r := range c.Workloads {
		ui.Row(w,
			ui.Yellow(r.Name),
			ui.Cyan(fmt.Sprintf("%.2f %s", r.Single, r.Unit)),
			ui.Cyan(fmt.Sprintf("%.2f %s", r.Multi, r.Unit)))
	}
	ui.Row(w,
		ui.Bold(ui.White("Score")),
		ui.Green(fmt.Sprintf("%.0f pts", c.Score.Single)),
		ui.Green(fmt.Sprintf("%.0f pts", c.Score.Multi)))
	ui.KV("Threads used", fmt.Sprintf("%d (scaling x%.2f)", c.Threads, c.Score.Scaling))
}

// PrintMemory печатает пропускную способность памяти и задержку доступа.
func PrintMemory(m *MemBench) {
	ui.KV("Memory Write", fmt.Sprintf("%.2f GB/s", m.WriteGBs))
	ui.KV("Memory Read", fmt.Sprintf("%.2f GB/s", m.ReadGBs))
	ui.KV("Memory Copy", fmt.Sprintf("%.2f GB/s", m.CopyGBs))
	ui.KV("Random Access", fmt.Sprintf("%.1f ns", m.LatencyNs))
	ui.KV("Buffer Size", HumanBytes(m.BufferBytes))
}

var speedWidths = []int{19, 18, 20, 12}

// PrintSpeedtestHeader печатает заголовок таблицы speedtest.
// Отдельная функция нужна из-за живого вывода: заголовок печатается один раз
// перед первой измеренной строкой.
//
// Строка «Method» обязательна: цифры Ookla и Cloudflare получены по разным
// маршрутам, и без пометки скопированный на форум отчёт вводит в заблуждение.
func PrintSpeedtestHeader(method, set string) {
	ui.KV("Method", SpeedMethodLabel(method, set))
	ui.Row(speedWidths, ui.Bold("Node Name"), ui.Bold("Upload Speed"), ui.Bold("Download Speed"), ui.Bold("Latency"))
}

// PrintSpeedNode печатает одну строку speedtest сразу после измерения узла,
// чтобы пользователь видел прогресс, а не ждал минуты в тишине.
// У неудачного узла в третьей колонке показывается причина.
func PrintSpeedNode(n SpeedNode) {
	if n.Failed {
		ui.Row(speedWidths, ui.Purple(Truncate(n.Name, 18)), ui.Red("Test failed"), ui.Dim(Truncate(n.Err, 30)), "")
		return
	}
	ui.Row(speedWidths,
		ui.Purple(Truncate(n.Name, 18)),
		ui.Cyan(Speed(n.UploadMbps)),
		ui.Cyan(Speed(n.DownMbps)),
		ui.Cyan(Latency(n.LatencyMs)))
}

// PrintIP печатает блок «чей это адрес»: сначала геолокация по IPv4 и IPv6,
// затем отдельной секцией — регистрационная запись RDAP (владелец сети,
// диапазон, реестр, даты и abuse-контакт).
func PrintIP(i *IPInfo) {
	if g := i.IPv4; g != nil {
		printGeo("IPv4", g)
	}
	if g := i.IPv6; g != nil {
		printGeo("IPv6", g)
	}
	if r := i.RDAP; r != nil {
		ui.Blank()
		ui.Header("IP Registration (RDAP)")
		if r.Name != "" {
			ui.KV("Network Name", r.Name)
		}
		if r.Handle != "" {
			ui.KV("Handle", r.Handle)
		}
		if len(r.CIDR) > 0 {
			ui.KV("CIDR", strings.Join(r.CIDR, ", "))
		} else if r.StartIP != "" {
			ui.KV("Range", r.StartIP+" - "+r.EndIP)
		}
		if r.Type != "" {
			ui.KV("Allocation Type", r.Type)
		}
		if r.Registry != "" {
			ui.KV("Registry", r.Registry)
		}
		if r.Country != "" {
			ui.KV("Country", r.Country)
		}
		if r.Registered != "" {
			ui.KV("Registered", r.Registered)
		}
		if r.Updated != "" {
			ui.KV("Last Updated", r.Updated)
		}
		for _, e := range r.Entities {
			ui.KV(shortRoles(e.Roles), JoinNonEmpty(" · ", e.Name, e.Handle, e.Country))
		}
		if r.Abuse != nil {
			ui.KV("Abuse Contact", JoinNonEmpty(" · ", r.Abuse.Name, r.Abuse.Email, r.Abuse.Phone))
		}
		for _, rm := range r.Remarks {
			ui.Note(Truncate(rm, ui.Width-4))
		}
	}
}

func printGeo(family string, g *Geo) {
	ui.KV(family+" Address", g.IP)
	ui.KV("ASN", JoinNonEmpty(" ", g.ASN, g.ASName))
	if g.Org != "" {
		ui.KV("Organization", g.Org)
	}
	if g.ISP != "" && g.ISP != g.Org {
		ui.KV("ISP", g.ISP)
	}
	ui.KV("Location", JoinNonEmpty(", ", g.City, g.Region, g.Country))
	if g.Timezone != "" {
		ui.KV("Timezone", g.Timezone)
	}
	if g.Lat != 0 || g.Lon != 0 {
		ui.KV("Coordinates", fmt.Sprintf("%.4f, %.4f", g.Lat, g.Lon))
	}
	flags := []string{}
	if g.Hosting {
		flags = append(flags, "hosting/datacenter")
	}
	if g.Proxy {
		flags = append(flags, "proxy/vpn")
	}
	if g.Mobile {
		flags = append(flags, "mobile")
	}
	if len(flags) > 0 {
		ui.KVRaw("IP Type", ui.Yellow(strings.Join(flags, ", ")))
	} else {
		ui.KV("IP Type", "residential/unclassified")
	}
	if g.Source != "" {
		ui.KV("Data Source", g.Source)
	}
}

// shortRoles превращает роли RDAP в компактный ключ строки, например
// "Admin/Tech". Ролей у одной записи бывает много, а ширина колонки ключа —
// 19 символов, поэтому берём максимум две и сокращаем названия.
func shortRoles(roles []string) string {
	if len(roles) == 0 {
		return "Entity"
	}
	short := map[string]string{
		"registrant": "Registrant", "administrative": "Admin", "technical": "Tech",
		"abuse": "Abuse", "noc": "NOC", "reseller": "Reseller", "sponsor": "Sponsor",
		"registrar": "Registrar", "proxy": "Proxy", "notifications": "Notify",
	}
	var out []string
	for _, r := range roles {
		if s, ok := short[strings.ToLower(r)]; ok {
			out = append(out, s)
		} else {
			out = append(out, title(r))
		}
		if len(out) == 2 {
			break
		}
	}
	return Truncate(strings.Join(out, "/"), 18)
}

func title(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// PrintBlacklist печатает итог опроса чёрных списков.
// Считаются отдельно: чистые зоны, попадания и «неопределённые» — зоны,
// отказавшие публичному резолверу. Смешивать их нельзя: отказ Spamhaus не
// означает, что адрес чистый, но и попаданием не является.
func PrintBlacklist(b *Blacklist) {
	ui.KV("Checked IP", b.IP)
	if b.Resolver != "" {
		ui.KV("Resolver", b.Resolver)
	}
	var clean, unavailable int
	for _, e := range b.Entries {
		switch e.Status {
		case "clean":
			clean++
		case "unavailable", "error":
			unavailable++
		}
	}
	status := ui.Green(fmt.Sprintf("clean on %d lists", clean))
	if b.ListedCount > 0 {
		status = ui.Red(fmt.Sprintf("listed on %d of %d lists", b.ListedCount, b.Checked))
	}
	if unavailable > 0 {
		status += ui.Dim(fmt.Sprintf(" (%d inconclusive)", unavailable))
	}
	ui.KVRaw("Result", status)
	w := []int{28, 16, 24}
	for _, e := range b.Entries {
		var st string
		switch e.Status {
		case "listed":
			st = ui.Red("LISTED")
		case "clean":
			st = ui.Green("clean")
		case "unavailable":
			st = ui.Yellow("unavailable")
		default:
			st = ui.Dim("error")
		}
		ui.Row(w, ui.Cyan(e.Zone), st, ui.Dim(JoinNonEmpty(" ", e.Code, e.Reason)))
	}
}

// PrintUnblock печатает таблицу доступности сервисов.
// Отдельный статус Unknown — сервис ответил, но подтвердить регион нечем;
// печатать в этом случае «Yes» было бы враньём (см. checks.go).
func PrintUnblock(u *Unblock) {
	w := []int{22, 16, 30}
	for _, it := range u.Items {
		var st string
		switch it.Status {
		case "yes":
			st = ui.Green("Yes")
		case "no":
			st = ui.Red("No")
		case "restricted":
			st = ui.Yellow("Restricted")
		case "unknown":
			st = ui.Yellow("Unknown")
		default:
			st = ui.Dim("Failed")
		}
		ui.Row(w, ui.Cyan(it.Service), st, ui.Dim(JoinNonEmpty(" ", it.Region, it.Detail)))
	}
}

// PrintBlocking печатает доступность мессенджеров и соцсетей: строка сервиса
// с общим вердиктом, под ней его адреса с причиной. Причина здесь главное —
// она отвечает на вопрос «чем режут»: DNS, IP, SNI или замедлением.
func PrintBlocking(b *Blocking) {
	reachable := 0
	for _, s := range b.Services {
		if s.Status == "ok" {
			reachable++
		}
	}
	result := ui.Green(fmt.Sprintf("all %d services reachable", len(b.Services)))
	if reachable < len(b.Services) {
		result = ui.Yellow(fmt.Sprintf("%d of %d services reachable", reachable, len(b.Services)))
	}
	ui.KVRaw("Result", result)
	w := []int{30, 12}
	for _, s := range b.Services {
		ui.Row(w, ui.Purple(s.Name), blockLabel(s.Status))
		for _, p := range s.Probes {
			ui.Row(w, "  "+ui.Cyan(p.Host), blockLabel(p.Status), ui.Dim(Truncate(p.Detail, 28)))
		}
	}
}

func blockLabel(status string) string {
	switch status {
	case "ok":
		return ui.Green("OK")
	case "blocked":
		return ui.Red("Blocked")
	case "throttled":
		return ui.Yellow("Throttled")
	case "partial":
		return ui.Yellow("Partial")
	default:
		return ui.Dim("Failed")
	}
}

// PrintNetwork печатает всю сетевую диагностику: задержки до якорей,
// исходящие порты, параметры стека и трассировки. Секции с пустыми данными
// пропускаются, поэтому вывод без root короче.
func PrintNetwork(n *NetDiag) {
	if len(n.Latency) > 0 {
		w := []int{22, 16, 14, 18}
		ui.Row(w, ui.Bold("Anchor"), ui.Bold("RTT"), ui.Bold("Method"), ui.Bold("Loss"))
		for _, l := range n.Latency {
			if l.Err != "" {
				ui.Row(w, ui.Purple(l.Name), ui.Red("unreachable"), ui.Dim(l.Method), ui.Dim(Truncate(l.Err, 17)))
				continue
			}
			loss := ""
			if l.LossPc > 0 {
				loss = ui.Yellow(fmt.Sprintf("%.0f%% loss", l.LossPc))
			}
			ui.Row(w, ui.Purple(l.Name), ui.Cyan(Latency(l.RTTMs)), ui.Dim(l.Method), loss)
		}
	}
	if len(n.Ports) > 0 {
		ui.Blank()
		ui.Header("Outbound Ports")
		w := []int{12, 16, 18, 20}
		for _, p := range n.Ports {
			st := ui.Green("open")
			if !p.Open {
				st = ui.Red("blocked")
			}
			ui.Row(w, ui.Cyan(fmt.Sprintf("%d/tcp", p.Port)), ui.Yellow(p.Service), st, ui.Dim(p.Host))
		}
	}
	if s := n.Stack; s != nil {
		ui.Blank()
		ui.Header("Network Stack")
		ui.KVRaw("IPv4 / IPv6", onlineOffline(s.IPv4)+" / "+onlineOffline(s.IPv6))
		if s.MTU > 0 {
			ui.KV("Path MTU", fmt.Sprintf("%d bytes", s.MTU))
		}
		if s.CCCurrent != "" {
			ui.KV("Congestion Ctrl", s.CCCurrent)
		}
		if len(s.CCAvail) > 0 {
			ui.KV("CC Available", strings.Join(s.CCAvail, " "))
		}
		ui.KVRaw("BBR", enabled(s.BBR))
		if len(s.Resolvers) > 0 {
			ui.KV("DNS Resolvers", strings.Join(s.Resolvers, ", "))
		}
		if s.ResolverIP != "" {
			ui.KV("Public Resolver", JoinNonEmpty(" ", s.ResolverIP, s.ResolverCC))
		}
	}
	for _, t := range n.Traces {
		ui.Blank()
		ui.Header("Traceroute → " + t.Target)
		if t.Note != "" {
			ui.Note(Truncate(t.Note, ui.Width-4))
		}
		w := []int{5, 20, 34, 12}
		for _, h := range t.Hops {
			ip := h.IP
			if ip == "" {
				ip = "*"
			}
			ui.Row(w,
				ui.Dim(fmt.Sprintf("%2d", h.N)),
				ui.Cyan(ip),
				ui.Yellow(Truncate(JoinNonEmpty(" ", h.ASN, h.Org, h.Host), 33)),
				ui.Dim(Latency(h.RTTMs)))
		}
	}
}

// Сколько строк сырой записи WHOIS печатать в терминал. Записи бывают на
// двести строк с юридическими примечаниями реестра; целиком они уходят в
// -json и -md, а на экране от них нужен только сам ответ.
const maxRawLines = 40

// PrintDomain печатает отчёт по домену: регистрационную запись, ответы DNS
// и — в конце, приглушённым текстом — сырой ответ WHOIS.
//
// Свободный домен обрабатывается отдельной веткой: у него нет ни дат, ни
// регистратора, и печатать пустые строки вместо честного «available» значило
// бы выдать отсутствие записи за сбой.
func PrintDomain(d *DomainInfo) {
	ui.KV("Domain", JoinNonEmpty(" · ", d.Domain, d.Unicode))
	if d.Available {
		ui.KVRaw("Registration", ui.Green("available (no WHOIS record)"))
		printDomainDNS(d.DNS)
		return
	}
	ui.KVRaw("Registration", ui.Yes("registered"))
	if d.Registered != "" {
		ui.KV("Registered", d.Registered)
	}
	if d.Expires != "" {
		ui.KVRaw("Expires", expiry(d.Expires, d.ExpiresDays))
	}
	if d.Updated != "" {
		ui.KV("Last Updated", d.Updated)
	}
	if r := d.Registrar; r != nil {
		name := r.Name
		if r.IANAID != "" {
			name = JoinNonEmpty(" · ", name, "IANA "+r.IANAID)
		}
		if name != "" {
			ui.KV("Registrar", name)
		}
		if r.URL != "" {
			ui.KV("Registrar URL", Truncate(r.URL, ui.Width-22))
		}
		if abuse := JoinNonEmpty(" · ", r.AbuseEmail, r.AbusePhone); abuse != "" {
			ui.KV("Abuse Contact", Truncate(abuse, ui.Width-22))
		}
	}
	if len(d.Status) > 0 {
		ui.KVList("EPP Status", d.Status)
	}
	if len(d.NameServers) > 0 {
		ui.KVList("Name Servers", d.NameServers)
	}
	if d.DNSSEC != "" {
		ui.KV("DNSSEC", d.DNSSEC)
	}
	for _, c := range d.Contacts {
		v := JoinNonEmpty(" · ", c.Org, c.Name, c.Email, c.Web, c.Phone, JoinNonEmpty(", ", c.Location, c.Country))
		if v != "" {
			ui.KV(contactTitle(c.Role), Truncate(v, ui.Width-22))
		}
	}
	if len(d.Sources) > 0 {
		ui.KV("Data Source", Truncate(strings.Join(d.Sources, ", "), ui.Width-22))
	}
	for _, n := range d.Notes {
		ui.Note(Truncate(n, ui.Width-4))
	}

	printDomainDNS(d.DNS)
	printRawWhois(d.Raw)
}

// expiry раскрашивает дату окончания регистрации: просроченный домен — красный,
// меньше месяца до продления — жёлтый. Именно ради этой строки отчёт по домену
// чаще всего и открывают.
func expiry(date string, days int) string {
	switch {
	case days < 0:
		return ui.Red(fmt.Sprintf("%s (expired %d days ago)", date, -days))
	case days == 0:
		return ui.Cyan(date)
	case days <= 30:
		return ui.Yellow(fmt.Sprintf("%s (in %d days)", date, days))
	}
	return ui.Cyan(fmt.Sprintf("%s (in %d days)", date, days))
}

// contactTitle переводит роль контакта в подпись строки.
func contactTitle(role string) string {
	switch role {
	case "registrant":
		return "Registrant"
	case "admin":
		return "Admin Contact"
	case "tech":
		return "Tech Contact"
	case "billing":
		return "Billing Contact"
	}
	return title(role)
}

// printDomainDNS печатает то, что домен отвечает в DNS сейчас, — отдельной
// секцией, потому что это данные другой природы: запись WHOIS меняется раз в
// год, а A-запись может измениться к следующему прогону.
func printDomainDNS(dns *DomainDNS) {
	if dns == nil {
		return
	}
	ui.Blank()
	ui.Header("DNS Records")
	if dns.CNAME != "" {
		ui.KV("CNAME", dns.CNAME)
	}
	ui.KVList("A", dns.A)
	ui.KVList("AAAA", dns.AAAA)
	ui.KVList("NS", dns.NS)
	ui.KVList("MX", dns.MX)
	ui.KVList("TXT", dns.TXT)
	if dns.TXTMore > 0 {
		ui.Note(fmt.Sprintf("%d more TXT records omitted", dns.TXTMore))
	}
	if dns.Err != "" {
		ui.KVRaw("Resolver", ui.Yellow(dns.Err))
	}
}

// printRawWhois печатает ответ реестра как есть — обрезая длинные строки по
// ширине рамки, иначе они переносятся и ломают её.
//
// Текст записи печатается обычным белым, а не Dim: приглушённый серый на
// тёмной теме SSH-клиента почти не читается, а здесь это не служебная
// пометка, а содержимое, ради которого тест и запускают.
func printRawWhois(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	ui.Blank()
	ui.Header("Raw WHOIS Record")
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		if i == maxRawLines {
			ui.Note(fmt.Sprintf("… %d more lines (full record goes to -json and -md)", len(lines)-maxRawLines))
			break
		}
		ui.Line(ui.White(Truncate(strings.TrimRight(l, " \t\r"), ui.Width)))
	}
}

// PrintFailures печатает секцию Notes — список тестов, которые не
// завершились, с причиной. Нужна, чтобы отсутствие секции в отчёте нельзя
// было принять за «всё хорошо».
func PrintFailures(r *Report) {
	if len(r.Failures) == 0 {
		return
	}
	ui.Blank()
	ui.Header("Notes")
	for _, f := range r.Failures {
		ui.Warn(f.Test + ": " + Truncate(f.Reason, ui.Width-12))
	}
}
