package report

// markdown.go — экспорт отчёта в Markdown (флаг -md). Формат рассчитан на
// вставку в форум или тикет: таблицы вместо ANSI-рамки, без цветов.
// Значения форматируются теми же функциями из format.go, что и текстовый
// вывод, поэтому расхождений между форматами быть не может.

import (
	"fmt"
	"os"
	"strings"
)

// WriteMarkdown сохраняет отчёт в Markdown.
func WriteMarkdown(r *Report, path string) error {
	return os.WriteFile(path, []byte(Markdown(r)), 0o644)
}

// Markdown собирает весь отчёт в одну строку Markdown.
// Секции печатаются только если соответствующий тест выполнялся (указатель
// в модели не nil).
func Markdown(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ServerOk report\n\n")
	fmt.Fprintf(&b, "*Generated %s with ServerOk %s*\n\n", r.Generated.Format("2006-01-02 15:04:05 MST"), r.Version)

	if s := r.System; s != nil {
		b.WriteString("## System\n\n| Field | Value |\n|---|---|\n")
		// Поля, которых нет на этой платформе (кэш CPU на macOS, congestion
		// control вне Linux), пропускаются, а не печатаются пустой строкой
		// таблицы.
		row := func(k, v string) {
			if strings.TrimSpace(v) != "" {
				fmt.Fprintf(&b, "| %s | %s |\n", k, v)
			}
		}
		row("CPU Model", s.CPUModel)
		row("CPU Cores", fmt.Sprintf("%d @ %.0f MHz", s.CPUCores, s.CPUFreqMHz))
		row("CPU Cache", s.CPUCache)
		row("AES-NI", yesNo(s.AESNI))
		row("VM-x/AMD-V", yesNo(s.VirtExt))
		row("Total Disk", UsedOf(s.DiskTotal, s.DiskUsed))
		row("Total RAM", UsedOf(s.RAMTotal, s.RAMUsed))
		row("Total Swap", UsedOf(s.SwapTotal, s.SwapUsed))
		row("Uptime", Uptime(s.UptimeSec))
		row("Load Average", fmt.Sprintf("%.2f, %.2f, %.2f", s.LoadAvg[0], s.LoadAvg[1], s.LoadAvg[2]))
		row("OS", s.OS)
		row("Arch", JoinNonEmpty(" ", s.Arch, s.ArchBits))
		row("Kernel", s.Kernel)
		row("TCP CC", s.TCPCongestion)
		row("Virtualization", s.Virtualization)
		row("IPv4 / IPv6", yesNo(s.IPv4Online)+" / "+yesNo(s.IPv6Online))
		row("Organization", s.Org)
		row("Location", s.Location)
		row("Region", s.Region)
		b.WriteString("\n")
	}

	if c := r.CPU; c != nil {
		b.WriteString("## CPU benchmark\n\n| Workload | Single-thread | Multi-thread |\n|---|---|---|\n")
		for _, w := range c.Workloads {
			fmt.Fprintf(&b, "| %s | %.2f %s | %.2f %s |\n", w.Name, w.Single, w.Unit, w.Multi, w.Unit)
		}
		fmt.Fprintf(&b, "| **Score** | **%.0f pts** | **%.0f pts** |\n\n", c.Score.Single, c.Score.Multi)
	}

	if m := r.Memory; m != nil {
		b.WriteString("## Memory\n\n| Metric | Value |\n|---|---|\n")
		fmt.Fprintf(&b, "| Write | %.2f GB/s |\n| Read | %.2f GB/s |\n| Copy | %.2f GB/s |\n| Random access | %.1f ns |\n\n",
			m.WriteGBs, m.ReadGBs, m.CopyGBs, m.LatencyNs)
	}

	if d := r.Disk; d != nil {
		b.WriteString("## Disk I/O\n\n| Run | Speed |\n|---|---|\n")
		for i, v := range d.Runs {
			fmt.Fprintf(&b, "| %s run | %s |\n", ordinal(i+1), MBs(v))
		}
		fmt.Fprintf(&b, "| **Average** | **%s** |\n", MBs(d.Average))
		if d.RandWrIOPS > 0 {
			fmt.Fprintf(&b, "| 4K random write | %.0f IOPS |\n", d.RandWrIOPS)
		}
		b.WriteString("\n")
	}

	if s := r.Speedtest; s != nil {
		b.WriteString("## Speedtest\n\n")
		fmt.Fprintf(&b, "Method: %s\n\n", SpeedMethodLabel(s.Method, s.Set))
		b.WriteString("| Node | Upload | Download | Latency |\n|---|---|---|---|\n")
		for _, n := range s.Nodes {
			if n.Failed {
				fmt.Fprintf(&b, "| %s | Test failed | | |\n", n.Name)
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", n.Name, Speed(n.UploadMbps), Speed(n.DownMbps), Latency(n.LatencyMs))
		}
		b.WriteString("\n")
	}

	if i := r.IP; i != nil {
		b.WriteString("## IP information\n\n| Field | Value |\n|---|---|\n")
		if g := i.IPv4; g != nil {
			fmt.Fprintf(&b, "| IPv4 | %s |\n| ASN | %s |\n| Location | %s |\n| IP type | %s |\n",
				g.IP, JoinNonEmpty(" ", g.ASN, g.ASName), JoinNonEmpty(", ", g.City, g.Region, g.Country), ipType(g))
		}
		if g := i.IPv6; g != nil {
			fmt.Fprintf(&b, "| IPv6 | %s |\n", g.IP)
		}
		if d := i.RDAP; d != nil {
			fmt.Fprintf(&b, "| Network | %s |\n| CIDR | %s |\n| Registry | %s |\n| Registered | %s |\n",
				d.Name, strings.Join(d.CIDR, ", "), d.Registry, d.Registered)
			for _, e := range d.Entities {
				fmt.Fprintf(&b, "| %s | %s |\n", strings.Join(e.Roles, "/"), JoinNonEmpty(" · ", e.Name, e.Handle, e.Country))
			}
			if d.Abuse != nil {
				fmt.Fprintf(&b, "| Abuse contact | %s |\n", JoinNonEmpty(" · ", d.Abuse.Name, d.Abuse.Email, d.Abuse.Phone))
			}
		}
		b.WriteString("\n")
	}

	if bl := r.Blacklist; bl != nil {
		fmt.Fprintf(&b, "## IP reputation\n\nListed on **%d of %d** DNSBLs.\n\n", bl.ListedCount, bl.Checked)
		b.WriteString("| Zone | Status | Code |\n|---|---|---|\n")
		for _, e := range bl.Entries {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", e.Zone, e.Status, e.Code)
		}
		b.WriteString("\n")
	}

	if u := r.Unblock; u != nil {
		b.WriteString("## Service availability\n\n| Service | Status | Region |\n|---|---|---|\n")
		for _, it := range u.Items {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", it.Service, it.Status, JoinNonEmpty(" ", it.Region, it.Detail))
		}
		b.WriteString("\n")
	}

	if bk := r.Blocking; bk != nil {
		b.WriteString("## Service blocking\n\n| Service | Endpoint | Status | Detail |\n|---|---|---|---|\n")
		for _, s := range bk.Services {
			fmt.Fprintf(&b, "| **%s** | | **%s** | |\n", s.Name, s.Status)
			for _, p := range s.Probes {
				fmt.Fprintf(&b, "| | %s | %s | %s |\n", p.Host, p.Status, p.Detail)
			}
		}
		b.WriteString("\n")
	}

	if n := r.Network; n != nil {
		if len(n.Latency) > 0 {
			b.WriteString("## Latency\n\n| Anchor | RTT | Method |\n|---|---|---|\n")
			for _, l := range n.Latency {
				v := Latency(l.RTTMs)
				if l.Err != "" {
					v = "unreachable"
				}
				fmt.Fprintf(&b, "| %s | %s | %s |\n", l.Name, v, l.Method)
			}
			b.WriteString("\n")
		}
		if len(n.Ports) > 0 {
			b.WriteString("## Outbound ports\n\n| Port | Service | Status |\n|---|---|---|\n")
			for _, p := range n.Ports {
				fmt.Fprintf(&b, "| %d | %s | %s |\n", p.Port, p.Service, openClosed(p.Open))
			}
			b.WriteString("\n")
		}
		if s := n.Stack; s != nil {
			b.WriteString("## Network stack\n\n| Field | Value |\n|---|---|\n")
			fmt.Fprintf(&b, "| IPv4 / IPv6 | %s / %s |\n| MTU | %d |\n| Congestion control | %s |\n| BBR | %s |\n| Public resolver | %s |\n\n",
				yesNo(s.IPv4), yesNo(s.IPv6), s.MTU, s.CCCurrent, yesNo(s.BBR), JoinNonEmpty(" ", s.ResolverIP, s.ResolverCC))
		}
		for _, t := range n.Traces {
			fmt.Fprintf(&b, "## Traceroute — %s\n\n", t.Target)
			if t.Note != "" {
				fmt.Fprintf(&b, "*%s*\n\n", t.Note)
			}
			if len(t.Hops) > 0 {
				b.WriteString("| # | IP | AS | RTT |\n|---|---|---|---|\n")
				for _, h := range t.Hops {
					ip := h.IP
					if ip == "" {
						ip = "*"
					}
					fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", h.N, ip, JoinNonEmpty(" ", h.ASN, h.Org), Latency(h.RTTMs))
				}
				b.WriteString("\n")
			}
		}
	}

	if d := r.Domain; d != nil {
		b.WriteString("## Domain\n\n| Field | Value |\n|---|---|\n")
		row := func(k, v string) {
			if strings.TrimSpace(v) != "" {
				fmt.Fprintf(&b, "| %s | %s |\n", k, v)
			}
		}
		row("Domain", JoinNonEmpty(" / ", d.Domain, d.Unicode))
		if d.Available {
			row("Registration", "available")
		} else {
			row("Registration", "registered")
		}
		row("Registered", d.Registered)
		row("Expires", expiryPlain(d.Expires, d.ExpiresDays))
		row("Updated", d.Updated)
		if rg := d.Registrar; rg != nil {
			row("Registrar", JoinNonEmpty(" · ", rg.Name, rg.IANAID))
			row("Registrar URL", rg.URL)
			row("Abuse contact", JoinNonEmpty(" · ", rg.AbuseEmail, rg.AbusePhone))
		}
		row("Status", strings.Join(d.Status, ", "))
		row("Name servers", strings.Join(d.NameServers, ", "))
		row("DNSSEC", d.DNSSEC)
		for _, c := range d.Contacts {
			row(contactTitle(c.Role), JoinNonEmpty(" · ", c.Org, c.Name, c.Email, c.Web, c.Phone, JoinNonEmpty(", ", c.Location, c.Country)))
		}
		row("Sources", strings.Join(d.Sources, ", "))
		b.WriteString("\n")
		if dns := d.DNS; dns != nil {
			b.WriteString("### DNS records\n\n| Type | Value |\n|---|---|\n")
			row("CNAME", dns.CNAME)
			row("A", strings.Join(dns.A, ", "))
			row("AAAA", strings.Join(dns.AAAA, ", "))
			row("NS", strings.Join(dns.NS, ", "))
			row("MX", strings.Join(dns.MX, ", "))
			row("TXT", strings.Join(dns.TXT, "<br>"))
			row("Resolver", dns.Err)
			b.WriteString("\n")
		}
		if raw := strings.TrimSpace(d.Raw); raw != "" {
			// Сырая запись — в блоке кода: в ней есть символы, которые
			// Markdown иначе истолкует как разметку.
			fmt.Fprintf(&b, "### Raw WHOIS record\n\n```\n%s\n```\n\n", raw)
		}
	}

	if len(r.Failures) > 0 {
		b.WriteString("## Notes\n\n")
		for _, f := range r.Failures {
			fmt.Fprintf(&b, "- **%s**: %s\n", f.Test, f.Reason)
		}
	}
	return b.String()
}

// yesNo, openClosed и ipType — короткие переводы булевых полей модели в
// текст таблицы (в Markdown нет цвета, поэтому ✓/✗ заменяются словами).
func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func openClosed(b bool) string {
	if b {
		return "open"
	}
	return "blocked"
}

// expiryPlain — та же строка «дата (осталось дней)», что и в терминале, но
// без цвета: в Markdown его нет.
func expiryPlain(date string, days int) string {
	switch {
	case date == "" || days == 0:
		return date
	case days < 0:
		return fmt.Sprintf("%s (expired %d days ago)", date, -days)
	}
	return fmt.Sprintf("%s (in %d days)", date, days)
}

func ipType(g *Geo) string {
	var flags []string
	if g.Hosting {
		flags = append(flags, "hosting")
	}
	if g.Proxy {
		flags = append(flags, "proxy")
	}
	if g.Mobile {
		flags = append(flags, "mobile")
	}
	if len(flags) == 0 {
		return "residential/unclassified"
	}
	return strings.Join(flags, ", ")
}
