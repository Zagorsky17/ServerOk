package main

import (
	"errors"
	"fmt"

	"github.com/Zagorsky17/ServerOk/internal/bench"
	"github.com/Zagorsky17/ServerOk/internal/blocking"
	"github.com/Zagorsky17/ServerOk/internal/ipinfo"
	"github.com/Zagorsky17/ServerOk/internal/netcheck"
	"github.com/Zagorsky17/ServerOk/internal/netutil"
	"github.com/Zagorsky17/ServerOk/internal/report"
	"github.com/Zagorsky17/ServerOk/internal/runner"
	"github.com/Zagorsky17/ServerOk/internal/sysinfo"
	"github.com/Zagorsky17/ServerOk/internal/unblock"
	"github.com/Zagorsky17/ServerOk/internal/whois"
)

// tests.go — единственное место, где объявлены тесты.
//
// Из этого списка автоматически получаются: пункты меню, значения флага -test,
// вывод -list и порядок секций отчёта. Чтобы добавить тест, достаточно
// дописать сюда одну запись runner.Test — трогать меню, парсер флагов или
// рендер не нужно.
//
// В каждой записи:
//   ID/Title — идентификатор и заголовок секции;
//   Order    — место в отчёте (шаг 10, чтобы было куда вставлять);
//   NeedRoot — тест деградирует без прав root (выводится предупреждение);
//   Run      — что делать: получить данные и положить их в c.Rep;
//   Print    — как показать результат; nil означает, что Run печатает сам.

// buildRegistry собирает реестр тестов.
func buildRegistry() *runner.Registry {
	return runner.New(
		runner.Test{
			ID: "system", Title: "System Information", Order: 10,
			Run: func(c *runner.Context) error {
				s, err := sysinfo.Collect(c, c.Opts.SkipIPv6)
				if err != nil {
					return err
				}
				c.Rep.System = s
				return nil
			},
			Print: func(r *report.Report) { report.PrintSystem(r.System) },
		},
		runner.Test{
			ID: "cpu", Title: "CPU Benchmark", Order: 20,
			Run: func(c *runner.Context) error {
				res, err := bench.CPU(c, c.Opts.CPUSecs, c.Status)
				if err != nil {
					return err
				}
				c.Rep.CPU = res
				return nil
			},
			Print: func(r *report.Report) { report.PrintCPU(r.CPU) },
		},
		runner.Test{
			ID: "memory", Title: "Memory Benchmark", Order: 30,
			Run: func(c *runner.Context) error {
				res, err := bench.Memory(c, c.Status)
				if err != nil {
					return err
				}
				c.Rep.Memory = res
				return nil
			},
			Print: func(r *report.Report) { report.PrintMemory(r.Memory) },
		},
		runner.Test{
			ID: "disk", Title: "Disk I/O Speed", Order: 40,
			Run: func(c *runner.Context) error {
				res, err := bench.Disk(c, c.Opts.DiskPath, c.Opts.DiskSize, 3, c.Status)
				if err != nil {
					return err
				}
				c.Rep.Disk = res
				return nil
			},
			Print: func(r *report.Report) { report.PrintDisk(r.Disk) },
		},
		runner.Test{
			ID: "speedtest", Title: "Network Speedtest", Order: 50,
			Run: func(c *runner.Context) error {
				// Speedtest печатает себя сам: строки появляются по мере
				// измерения узлов, поэтому поле Print у этого теста nil.
				printed := false
				onResult := func(n report.SpeedNode) {
					if c.Opts.Quiet {
						return
					}
					c.ClearStatus()
					if !printed {
						report.PrintSpeedtestHeader(c.Opts.SpeedMethod, c.Opts.Nodes)
						printed = true
					}
					report.PrintSpeedNode(n)
				}
				res, err := netcheck.Speedtest(c, c.Opts.SpeedMethod, c.Opts.Nodes, onResult, c.Status)
				if res != nil && len(res.Nodes) > 0 {
					// Сохраняем уже измеренные строки, даже если прогон
					// оборвался по лимиту времени теста.
					c.Rep.Speedtest = res
					return nil
				}
				return err
			},
		},
		runner.Test{
			ID: "ip", Title: "IP Location & Registration", Order: 60,
			Run: func(c *runner.Context) error {
				// Геолокация по обеим версиям адреса, затем RDAP по той из
				// них, что удалось определить.
				info := &report.IPInfo{}
				v4, err4 := ipinfo.LookupGeo(c, netutil.IPv4)
				if err4 == nil {
					info.IPv4 = v4
				}
				if !c.Opts.SkipIPv6 {
					if v6, err := ipinfo.LookupGeo(c, netutil.IPv6); err == nil {
						info.IPv6 = v6
					}
				}
				if info.IPv4 == nil && info.IPv6 == nil {
					return fmt.Errorf("cannot determine public IP: %w", err4)
				}
				target := info.IPv4
				if target == nil {
					target = info.IPv6
				}
				c.Status("ip: querying RDAP registry for %s", target.IP)
				// Неудача RDAP не проваливает тест целиком: геоданные уже
				// собраны и полезны, а причина уходит в секцию Notes.
				if rec, err := ipinfo.LookupRDAP(c, target.IP); err == nil {
					info.RDAP = rec
				} else {
					c.Rep.AddFailure("RDAP lookup", err.Error())
				}
				c.Rep.IP = info
				return nil
			},
			Print: func(r *report.Report) { report.PrintIP(r.IP) },
		},
		runner.Test{
			ID: "blacklist", Title: "IP Reputation (DNSBL)", Order: 70,
			Run: func(c *runner.Context) error {
				ip, err := publicIPv4(c)
				if err != nil {
					return err
				}
				res, err := ipinfo.CheckBlacklists(c, ip, func(done, total int) {
					c.Status("blacklist: %d/%d zones queried", done, total)
				})
				if err != nil {
					return err
				}
				c.Rep.Blacklist = res
				return nil
			},
			Print: func(r *report.Report) { report.PrintBlacklist(r.Blacklist) },
		},
		runner.Test{
			ID: "unblock", Title: "Streaming & AI Service Unblock", Order: 80,
			Run: func(c *runner.Context) error {
				c.Rep.Unblock = unblock.Run(c, c.Status)
				return nil
			},
			Print: func(r *report.Report) { report.PrintUnblock(r.Unblock) },
		},
		runner.Test{
			ID: "blocking", Title: "Messenger & Social Blocking", Order: 85,
			Run: func(c *runner.Context) error {
				res, err := blocking.Run(c, c.Status)
				if err != nil {
					return err
				}
				c.Rep.Blocking = res
				return nil
			},
			Print: func(r *report.Report) { report.PrintBlocking(r.Blocking) },
		},
		runner.Test{
			ID: "network", Title: "Routing, Latency & Ports", Order: 90, NeedRoot: true,
			Run: func(c *runner.Context) error {
				// Порядок подтестов: от дешёвых к дорогим, трассировки в конце.
				n := &report.NetDiag{}
				n.Latency = netcheck.Latency(c, c.Status)
				n.Ports = netcheck.Ports(c, c.Status)
				n.Stack = netcheck.Stack(c, c.Opts.SkipIPv6, c.Status)
				n.Traces = netcheck.Traceroute(c, c.Opts.TraceHops, c.Status)
				c.Rep.Network = n
				return nil
			},
			Print: func(r *report.Report) { report.PrintNetwork(r.Network) },
		},
		runner.Test{
			ID: "whois", Title: "Domain WHOIS Lookup", Order: 100,
			Run: func(c *runner.Context) error {
				// Единственный тест, которому нужен ввод пользователя: домен
				// спрашивается в меню перед прогоном или задаётся флагом
				// -domain (см. main.go). Без домена тесту делать нечего.
				if c.Opts.Domain == "" {
					return errors.New("no domain given: run with -domain example.com")
				}
				info, err := whois.Lookup(c, c.Opts.Domain, c.Status)
				if err != nil {
					return err
				}
				c.Rep.Domain = info
				return nil
			},
			Print: func(r *report.Report) { report.PrintDomain(r.Domain) },
		},
	)
}

// publicIPv4 возвращает публичный адрес, переиспользуя результат теста «IP
// Location», если тот уже отработал. Если тест не запускался (например,
// «-test blacklist»), адрес запрашивается сам — из кэша пакета ipinfo, так
// что лишнего обращения к API не будет.
func publicIPv4(c *runner.Context) (string, error) {
	if c.Rep.IP != nil && c.Rep.IP.IPv4 != nil {
		return c.Rep.IP.IPv4.IP, nil
	}
	g, err := ipinfo.LookupGeo(c, netutil.IPv4)
	if err != nil {
		return "", errors.New("cannot determine public IPv4 address")
	}
	return g.IP, nil
}
