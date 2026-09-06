# ServerOk

A single-binary VPS benchmark and network diagnostics tool, in the spirit of
`bench.sh` — but written in Go, with an interactive test menu and a much wider
set of checks: IP geolocation, **RDAP registration data (who the IP is
registered to)**, DNSBL reputation, streaming/AI service unblock checks,
routing diagnostics and **WHOIS lookups for any domain**.

No dependencies on the server: one static binary, no Python, no `speedtest-cli`,
no `whois`.

```
---------------- ServerOk — VPS Benchmark & Diagnostics ----------------
 Version           : v1.0.0
 Usage             : bash <(curl -sL .../install.sh)
--------------------------------------------------------------------------

------------------------- System Information -----------------------------
CPU Model          : AMD EPYC 7763 64-Core Processor
CPU Cores          : 1 @ 2449.998 MHz
CPU Cache          : 512 KB
AES-NI             : ✓ Enabled
VM-x/AMD-V         : ✓ Enabled
Total Disk         : 29.9 GB (2.9 GB Used)
Total RAM          : 1.9 GB (297.1 MB Used)
Total Swap         : 512.0 MB (0 KB Used)
System Uptime      : 0 days, 0 hour 5 min
Load Average       : 0.01, 0.12, 0.07
OS                 : Ubuntu 24.04.4 LTS
Arch               : amd64 (64 Bit)
Kernel             : 6.8.0-111-generic
TCP Congestion Ctrl: cubic
Virtualization     : KVM
IPv4/IPv6          : ✓ Online / ✗ Offline
Organization       : AS212743 ETERNITY INTERNATIONAL LIMITED
Location           : Kerkrade / NL
Region             : Limburg
```

## What it adds over `bench.sh`

**You pick where the speed is measured.** A server that looks fast to the
datacentre next door can be slow to the people you actually serve, so a single
number is the wrong answer — the direction is part of the question. Choose a
region (`eu`, `us`, `asia`, combinable), the quick three-node set, all sixteen
nodes, or Cloudflare's nearest edge for what a visitor pulling from a CDN gets.
The menu asks before the run, so the same server can be measured to Europe and
then to Asia without restarting anything:

```bash
serverok -test speedtest -nodes eu        # Europe only
serverok -test speedtest -nodes us,asia   # two regions in one run
serverok -test speedtest -speed-method cloudflare   # nearest CDN edge, ~20 s
```

**You can look up any domain without installing `whois`.** Menu item 10 takes a
domain (a pasted URL works) and prints the registration record: registrar and
abuse contact, creation, expiry and update dates with the days left, EPP status
codes, name servers, DNSSEC and the raw registry record — plus what the domain
answers in DNS right now (A, AAAA, NS, MX, TXT, CNAME), which the registry
record never tells you. Handy on a fresh VPS, where there is neither a `whois`
binary nor a package manager you feel like using:

```bash
serverok -test whois -domain example.com
```

## Quick start

Run it straight from GitHub — the script downloads the release binary for your
platform, verifies its SHA-256 and starts the menu:

```bash
bash <(curl -sL https://raw.githubusercontent.com/Zagorsky17/ServerOk/main/scripts/install.sh)
```

**This does not install anything.** The binary is unpacked into a temporary
directory, run from there and deleted when it exits — including on Ctrl+C or an
error. Nothing is written to `PATH`, `/usr/local/bin` is not touched, and no
config files, services or background processes are left behind. The only files
that survive a run are the reports you asked for with `-json` / `-md`, written
to the current directory. Installing is a separate, explicit step (`--install`,
below).

Run every test without the menu (also what happens automatically when there is
no terminal, e.g. in cron):

```bash
curl -sL https://raw.githubusercontent.com/Zagorsky17/ServerOk/main/scripts/install.sh | bash -s -- -all
```

Install it permanently:

```bash
bash <(curl -sL https://raw.githubusercontent.com/Zagorsky17/ServerOk/main/scripts/install.sh) --install
serverok
```

With `--install` the binary is moved out of the temporary directory into
`/usr/local/bin` (with `sudo` if needed) and stays there; the script prints
`installed to …` and exits without running any test, so the first run afterwards
is yours to start.

The installer refuses to run a binary it could not verify against
`checksums.txt`; `--no-verify` overrides that, and `--install=<dir>` picks the
target directory.

Or build it yourself:

```bash
go install github.com/Zagorsky17/ServerOk/cmd/serverok@latest
# or
git clone https://github.com/Zagorsky17/ServerOk && cd serverok && make build
```

### Running it after install

`--install` puts the binary on your `PATH` (`/usr/local/bin/serverok` by
default), so afterwards it's just:

```bash
serverok                 # interactive menu
serverok -all             # every test, no menu
serverok -test cpu,disk   # only the tests you name (see -list)
serverok -h                # all flags
```

If you built with `go install` instead, the binary lands in
`$(go env GOPATH)/bin/serverok` — make sure that directory is on your `PATH`.

### Uninstalling

Only needed if you installed it: a plain quick-start run leaves nothing to
remove. `serverok` is a single static binary with no config files, services or
background processes — removing it is just deleting the file:

```bash
sudo rm /usr/local/bin/serverok          # or wherever --install=<dir> put it
# built with `go install` instead?
rm "$(go env GOPATH)/bin/serverok"
```

## The menu

```
  1) System Information               6) IP Location & Registration
  2) CPU Benchmark                    7) IP Reputation (DNSBL)
  3) Memory Benchmark                 8) Streaming & AI Service Unblock
  4) Disk I/O Speed                   9) Routing, Latency & Ports
  5) Network Speedtest               10) Domain WHOIS Lookup
  a) Run all tests                    0) Quit
 Select (1-10 or a):
```

The menu comes back after every run, so you can keep picking tests; the tool
exits when you choose `0` or press Ctrl+C.

Item 10 asks which domain to look up (a pasted URL works — `https://example.com/x`
becomes `example.com`); pressing Enter without typing anything skips it. Passing
`-domain example.com` answers the question in advance, and without a domain the
lookup is left out of `-all` runs — it would have nothing to query.

## Tests

| Test | What it measures |
|---|---|
| **System Information** | CPU model/cores/cache, AES-NI and virtualization extensions, disk, RAM, swap, uptime, load, OS, kernel, TCP congestion control, hypervisor, IPv4/IPv6 reachability, ASN, location |
| **CPU Benchmark** | AES-256-GCM, SHA-256, gzip and a prime sieve, each single- and multi-threaded, plus a normalized score (≈1000 ≙ one modern server core) and the multi-core scaling factor |
| **Memory Benchmark** | Sequential write/read/copy bandwidth and random-access latency (pointer chase) |
| **Disk I/O Speed** | Three sequential 1 GiB writes with `fsync` (the `dd conv=fdatasync` equivalent), their average, and 4K random-write IOPS |
| **Network Speedtest** | Upload, download and latency, either against speedtest.net nodes (worldwide or one region — Europe, North America, Asia) or against the nearest Cloudflare edge. Ookla servers are found by city keyword, so dead sponsors are skipped automatically. Both methods measure over a fixed time window across several parallel connections and discard TCP slow start, which is what the official clients do — a single-connection test under-reports a fast link several times over |
| **IP Location & Registration** | Geolocation of the IPv4/IPv6 address (ASN, ISP, city, hosting/proxy flags) **and the RDAP record: network name, CIDR, allocation type, registry, registrant organization, registration dates and the abuse contact** |
| **IP Reputation (DNSBL)** | 14 blocklists (Spamhaus, Barracuda, SpamCop, SORBS, UCEPROTECT, …). Zones that refuse public resolvers are reported as inconclusive, not as "listed" |
| **Streaming & AI Service Unblock** | Netflix (full / originals-only / blocked), YouTube Premium, Disney+, Prime Video, Spotify, ChatGPT, Claude, TikTok, Steam — with the region each one resolves you to. A service that answers but does not reveal a region is reported as `Unknown`, never as a confident `Yes` |
| **Domain WHOIS Lookup** | Registration record for any domain from [whois.com](https://www.whois.com/) — registrar and IANA ID, abuse contact, creation/expiry/update dates with the days left, EPP status codes, name servers, DNSSEC and the registrant/admin/tech contacts, plus the raw registry record and the domain's live DNS (A, AAAA, NS, MX, TXT, CNAME). When whois.com answers with a captcha, the registry and registrar are queried directly over WHOIS port 43 |
| **Routing, Latency & Ports** | RTT to 11 global anchors (ICMP, falling back to TCP/443), outbound port reachability (25, 465, 587, … — does the provider block SMTP?), IPv4/IPv6, MTU, congestion control and BBR availability, DNS resolver identity, and traceroutes to four key networks with per-hop AS lookup |

## Flags

```
  -all                 run every test without showing the menu
  -test cpu,disk,ip    run specific tests (see -list)
  -list                list available tests
  -nodes fast|default|full|us|eu|asia|<ids>
                       speedtest node sets, combinable: -nodes eu,asia
                       (default: 9 worldwide nodes)
  -speed-method ookla|cloudflare
                       how to measure speed (default: ookla)
  -disk-size 1G        size of the disk test file
  -disk-path DIR       where to run the disk test (default: working directory)
  -domain example.com  domain for the WHOIS lookup (asked in the menu otherwise)
  -cpu-time 2.5        seconds per CPU workload and mode
  -json report.json    write the report as JSON
  -md report.md        write the report as Markdown (for forum posts)
  -no-color            disable ANSI colors
  -no-ipv6             skip all IPv6 lookups
  -quiet               no terminal output (use with -json/-md)
  -timeout 30m         time budget for one run
  -test-timeout 20m    per-test time limit
  -trace-hops 15       maximum traceroute hops
  -version
```

Examples:

```bash
serverok -all -nodes fast              # everything, quick speedtest
serverok -test speedtest -nodes eu     # speed to Europe only (us, asia too)
serverok -test speedtest -nodes us,asia          # two regions in one run
serverok -test speedtest -speed-method cloudflare  # nearest CDN edge, ~20 s
serverok -test ip,blacklist            # who owns this IP, and is it clean?
serverok -test whois -domain example.com   # registration record + live DNS
serverok -all -quiet -json report.json # for cron and dashboards
```

## Choosing how to measure speed

Two methods answer two different questions, so the tool ships both:

| Method | What it tells you | Cost |
|---|---|---|
| `ookla` (default) | How the server reaches the rest of the world — real transit to a named city. Pick a region with `-nodes us`, `-nodes eu` or `-nodes asia` instead of paying for all nine worldwide nodes | ~1 min per node |
| `cloudflare` | What a visitor pulling from a CDN gets. Anycast, so it always lands on the nearest Cloudflare edge (the colo code is in the report) and no region can be chosen | ~15 s total |

Picking the speedtest from the interactive menu asks which of these to run;
`-nodes` or `-speed-method` on the command line skips the question.

## Notes

* **Root is not required.** Only the traceroute test benefits from it: without
  root the tool uses the system `traceroute` binary, and skips the test if there
  is none. Latency probing falls back from ICMP to a TCP handshake automatically.
* **The Cloudflare method is anycast**: it always measures against the nearest
  Cloudflare edge (the colo code appears in the report), so it cannot be pointed
  at a region — use `-nodes us|eu|asia` with the Ookla method for that. Running
  it several times in a row may earn a temporary rate limit.
* **The disk test writes to the current directory** (override with `-disk-path`).
  It needs ~1.5 GiB free, otherwise it shrinks the test file to 256 MiB and says
  so. The temp file is always removed, including on Ctrl+C.
* **Service unblock checks are best effort.** They probe third-party endpoints
  that change over time; a Cloudflare bot challenge is reported as `Failed`
  rather than as a regional block, and reachability without a region marker is
  `Unknown` rather than `Yes` (disneyplus.com, for one, answers 200 worldwide).
  All of them live in `internal/unblock/checks.go`, one function each.
* **The WHOIS lookup reads whois.com first**, because its parsed record looks
  the same for every TLD. That page occasionally comes back as a captcha (most
  often for domains that turn out to be unregistered), so the tool then asks
  IANA which registry serves the TLD and queries the registry — and the
  registrar it points to — over port 43 itself. Providers that block outbound
  port 43 lose only that fallback.
* **Latency prefers ICMP and falls back to a TCP handshake**, and each row says
  which method produced the number. Replies are matched against the probe
  (peer, sequence, and id on a raw socket), so parallel anchors cannot borrow
  each other's timings.
* **Addresses returned by the geolocation APIs are validated** before they are
  used in an RDAP URL, a DNSBL query or a `whois` argument — ip-api.com is
  plain HTTP on the free tier, so its answer is treated as untrusted input.
* **Spamhaus and some other DNSBLs refuse queries from public resolvers**
  (1.1.1.1, 8.8.8.8) and answer `127.255.255.x`. That is shown as
  `unavailable`, never as a listing.
* The CPU score is a relative index, not a Geekbench number: it is the geometric
  mean of four workloads against a fixed baseline.

## Development

```bash
make lint     # gofmt + go vet + go test
make build    # ./serverok
make build-all VERSION=v1.0.0   # release archives for 7 platforms in dist/
```

Releases are cut by pushing a tag:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

`.github/workflows/release.yml` cross-compiles linux (amd64/arm64/386/arm),
darwin (amd64/arm64) and freebsd (amd64), generates `checksums.txt` and
publishes them to GitHub Releases — which is exactly what `scripts/install.sh`
downloads.

## Architecture

```
cmd/serverok/          flags, menu, test registry
internal/ui/          ANSI colors, frame, table and menu rendering
internal/runner/      test registry and execution (timeouts, Ctrl+C)
internal/sysinfo/     hardware and OS facts (/proc, sysfs, gopsutil)
internal/bench/       CPU, memory and disk benchmarks
internal/netcheck/    speedtest, latency, traceroute, ports, stack
internal/ipinfo/      geolocation, RDAP, DNSBL
internal/unblock/     streaming and AI service probes
internal/whois/       domain lookups: whois.com, WHOIS port 43, DNS records
internal/report/      data model + text/JSON/Markdown renderers
```

Adding a test means appending one `runner.Test` in
`cmd/serverok/tests.go` — the menu, the `-test` flag and the report order
all derive from that registry.

## Technologies

* **[Go](https://go.dev/)** (1.26) — the whole tool is a single dependency-free
  static binary; no runtime, no interpreter needed on the target server.
* **[gopsutil](https://github.com/shirou/gopsutil)** — cross-platform host,
  CPU, memory and disk facts for System Information.
* **[speedtest-go](https://github.com/showwin/speedtest-go)** — speedtest.net
  client for the Network Speedtest.
* **[golang.org/x/net](https://pkg.go.dev/golang.org/x/net)** — raw ICMP
  sockets for latency probing and IDN (punycode) conversion for domain lookups.
* **[golang.org/x/term](https://pkg.go.dev/golang.org/x/term)** — TTY
  detection for the interactive menu vs. non-interactive (`-all`/cron) mode.
* Everything else (RDAP, WHOIS, DNSBL, geolocation, unblock checks, traceroute) is
  plain `net`/`net/http` against public APIs and system tools — no other
  third-party dependencies.

## License

MIT — see [LICENSE](LICENSE).
