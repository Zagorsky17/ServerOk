// Пакет ipinfo отвечает на вопрос «чей это адрес»: определяет публичный IP
// сервера, его геолокацию и ASN (geo.go), регистрационную запись — на кого
// выделена сеть и куда жаловаться (rdap.go), и репутацию адреса в чёрных
// списках (blacklist.go).
//
// БЕЗОПАСНОСТЬ. Адрес, полученный от внешнего сервиса, — недоверенные данные:
// бесплатный тариф ip-api.com работает по обычному HTTP, то есть ответ можно
// подменить по пути. Дальше этот адрес уходит в URL запроса RDAP, в DNS-запрос
// к чёрным спискам и в аргументы командной строки whois (где ведущий дефис
// превратился бы во флаг, например -h — «спросить другой сервер»). Поэтому
// адрес проверяется и приводится к канонической форме сразу после разбора
// ответа — см. sanitize ниже и такую же проверку в LookupRDAP.
package ipinfo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
	"github.com/Zagorsky17/ServerOk/internal/report"
)

const lookupTimeout = 8 * time.Second

// Адреса сервисов вынесены в переменные, чтобы тесты могли подменить их на
// локальный httptest-сервер (см. geo_test.go).
//
// Провайдеры перебираются по очереди — первый, кто ответит осмысленно,
// побеждает. ip-api.com стоит первым, потому что отдаёт больше всего полей
// (ASN, признаки hosting/proxy), но работает по HTTP — отсюда проверка
// адреса в sanitize.
var (
	ipAPIURL   = "http://ip-api.com/json/?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
	ipAPIByIP  = "http://ip-api.com/json/"
	ipInfoURL  = "https://ipinfo.io/json"
	ipWhoIsURL = "https://ipwho.is/"
)

var (
	cacheMu sync.Mutex
	geoMemo = map[netutil.Family]*report.Geo{}
)

// LookupGeo определяет публичный адрес нужной версии IP и всё, что о нём
// известно провайдерам.
//
// Результат запоминается: шапка отчёта (sysinfo) и тест «IP Location»
// спрашивают одно и то же, а лимиты бесплатных API невелики. Неудача тоже
// кэшируется — иначе каждый следующий тест снова ждал бы таймаута.
//
// Наружу отдаётся копия, а не запомненный указатель. Он попадает прямо в
// отчёт (Rep.IP.IPv4), и общий на всех вызывающих указатель означал бы, что
// правка отчёта на месте незаметно меняет кэш, а два теста, читающих его
// одновременно, ловят гонку.
func LookupGeo(ctx context.Context, f netutil.Family) (*report.Geo, error) {
	cacheMu.Lock()
	if g, ok := geoMemo[f]; ok {
		cacheMu.Unlock()
		if g == nil {
			return nil, errors.New("no public address for " + string(f))
		}
		return cloneGeo(g), nil
	}
	cacheMu.Unlock()

	client := netutil.Client(f, lookupTimeout)
	defer client.CloseIdleConnections()
	var lastErr error
	for _, p := range providers {
		g, err := p(ctx, client)
		if err == nil && g != nil {
			if err := sanitize(g); err != nil {
				lastErr = err
				continue
			}
			cacheMu.Lock()
			geoMemo[f] = g
			cacheMu.Unlock()
			return cloneGeo(g), nil
		}
		if err != nil {
			lastErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	cacheMu.Lock()
	geoMemo[f] = nil
	cacheMu.Unlock()
	if lastErr == nil {
		lastErr = errors.New("all geolocation providers failed")
	}
	return nil, lastErr
}

// sanitize отбраковывает всё, что не является чистым IP-адресом, и приводит
// адрес к канонической форме.
//
// Это единственная точка, где ответ провайдера становится доверенным: дальше
// на него полагаются построение URL для RDAP, DNS-запросы к чёрным спискам и
// вызов whois. Проверка обязана оставаться здесь, а не у потребителей.
func sanitize(g *report.Geo) error {
	parsed := net.ParseIP(strings.TrimSpace(g.IP))
	if parsed == nil {
		return fmt.Errorf("provider %s returned a malformed address %q", g.Source, report.Truncate(g.IP, 40))
	}
	g.IP = parsed.String()
	return nil
}

// cloneGeo копирует запись целиком. Geo — плоская структура из строк, чисел
// и флагов, без срезов и указателей, поэтому поверхностной копии достаточно;
// при добавлении сюда среза копию придётся углубить.
func cloneGeo(g *report.Geo) *report.Geo {
	if g == nil {
		return nil
	}
	c := *g
	return &c
}

// ResetCache сбрасывает запомненные результаты. Нужен только тестам, чтобы
// они не влияли друг на друга.
func ResetCache() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	geoMemo = map[netutil.Family]*report.Geo{}
}

// providerFunc — единый интерфейс провайдера геолокации.
type providerFunc func(context.Context, *http.Client) (*report.Geo, error)

// providers перебираются по порядку; побеждает первый осмысленный ответ.
var providers = []providerFunc{fromIPAPI, fromIPInfo, fromIPWhoIs}

// fromIPAPI — ip-api.com: самый информативный источник, единственный, кто
// прямо сообщает признаки hosting/proxy/mobile. Работает по HTTP.
func fromIPAPI(ctx context.Context, c *http.Client) (*report.Geo, error) {
	resp, err := netutil.Get(ctx, c, ipAPIURL, 1<<16, nil)
	if err != nil {
		return nil, err
	}
	var v struct {
		Status     string  `json:"status"`
		Message    string  `json:"message"`
		Query      string  `json:"query"`
		Country    string  `json:"country"`
		CC         string  `json:"countryCode"`
		Region     string  `json:"region"`
		RegionName string  `json:"regionName"`
		City       string  `json:"city"`
		Lat        float64 `json:"lat"`
		Lon        float64 `json:"lon"`
		Timezone   string  `json:"timezone"`
		ISP        string  `json:"isp"`
		Org        string  `json:"org"`
		AS         string  `json:"as"`
		ASName     string  `json:"asname"`
		Mobile     bool    `json:"mobile"`
		Proxy      bool    `json:"proxy"`
		Hosting    bool    `json:"hosting"`
	}
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return nil, err
	}
	if v.Status != "success" {
		return nil, fmt.Errorf("ip-api: %s", v.Message)
	}
	asn, asName := splitAS(v.AS)
	if asName == "" {
		asName = v.ASName
	}
	return &report.Geo{
		IP: v.Query, ASN: asn, ASName: asName, Org: v.Org, ISP: v.ISP,
		Country: v.Country, CountryCode: v.CC, Region: v.RegionName, City: v.City,
		Timezone: v.Timezone, Lat: v.Lat, Lon: v.Lon,
		Hosting: v.Hosting, Proxy: v.Proxy, Mobile: v.Mobile, Source: "ip-api.com",
	}, nil
}

// fromIPInfo — ipinfo.io: HTTPS, но без признаков типа адреса; ASN и имя
// приходят одной строкой в поле org.
func fromIPInfo(ctx context.Context, c *http.Client) (*report.Geo, error) {
	resp, err := netutil.Get(ctx, c, ipInfoURL, 1<<16, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}
	var v struct {
		IP       string `json:"ip"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Loc      string `json:"loc"`
		Org      string `json:"org"`
		Timezone string `json:"timezone"`
	}
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return nil, err
	}
	if v.IP == "" {
		return nil, errors.New("ipinfo: empty response")
	}
	asn, asName := splitAS(v.Org)
	lat, lon := splitLoc(v.Loc)
	return &report.Geo{
		IP: v.IP, ASN: asn, ASName: asName, Org: asName, Country: v.Country,
		CountryCode: v.Country, Region: v.Region, City: v.City, Timezone: v.Timezone,
		Lat: lat, Lon: lon, Source: "ipinfo.io",
	}, nil
}

// fromIPWhoIs — ipwho.is: последний резерв, если первые два недоступны.
func fromIPWhoIs(ctx context.Context, c *http.Client) (*report.Geo, error) {
	resp, err := netutil.Get(ctx, c, ipWhoIsURL, 1<<16, nil)
	if err != nil {
		return nil, err
	}
	var v struct {
		Success  bool    `json:"success"`
		IP       string  `json:"ip"`
		Country  string  `json:"country"`
		CC       string  `json:"country_code"`
		Region   string  `json:"region"`
		City     string  `json:"city"`
		Lat      float64 `json:"latitude"`
		Lon      float64 `json:"longitude"`
		Timezone struct {
			ID string `json:"id"`
		} `json:"timezone"`
		Connection struct {
			ASN    int    `json:"asn"`
			Org    string `json:"org"`
			ISP    string `json:"isp"`
			Domain string `json:"domain"`
		} `json:"connection"`
	}
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return nil, err
	}
	if !v.Success || v.IP == "" {
		return nil, errors.New("ipwho.is: lookup failed")
	}
	asn := ""
	if v.Connection.ASN > 0 {
		asn = "AS" + strconv.Itoa(v.Connection.ASN)
	}
	return &report.Geo{
		IP: v.IP, ASN: asn, ASName: v.Connection.Org, Org: v.Connection.Org, ISP: v.Connection.ISP,
		Country: v.Country, CountryCode: v.CC, Region: v.Region, City: v.City,
		Timezone: v.Timezone.ID, Lat: v.Lat, Lon: v.Lon, Source: "ipwho.is",
	}, nil
}

// splitAS разбивает строку вида "AS212743 ETERNITY INTERNATIONAL LIMITED" на
// номер автономной системы и её название. Если префикса AS нет, вся строка
// считается названием.
func splitAS(s string) (asn, name string) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToUpper(s), "AS") {
		return "", s
	}
	parts := strings.SplitN(s, " ", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.TrimSpace(parts[1])
}

// splitLoc разбирает координаты из формата ipinfo.io — "50.1109,8.6821".
func splitLoc(loc string) (lat, lon float64) {
	parts := strings.Split(loc, ",")
	if len(parts) != 2 {
		return 0, 0
	}
	lat, _ = strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	lon, _ = strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	return lat, lon
}

// SummaryFields готовит три строки шапки отчёта: организация (ASN и её имя),
// "Город / Страна" и название региона — ровно как в bench.sh.
func SummaryFields(g *report.Geo) (org, location, region string) {
	if g == nil {
		return "", "", ""
	}
	org = report.JoinNonEmpty(" ", g.ASN, g.ASName)
	if org == "" {
		org = g.Org
	}
	location = report.JoinNonEmpty(" / ", g.City, g.CountryCode)
	return org, location, g.Region
}

// LookupGeoIP определяет геолокацию произвольного адреса (не своего).
// Используется, чтобы показать, где физически находится DNS-резолвер,
// которым мы ходим, — от этого зависит, какой регион видят стриминговые
// сервисы. Аргумент проверяется до запроса.
func LookupGeoIP(ctx context.Context, ip string) (*report.Geo, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return nil, fmt.Errorf("not an IP address: %q", report.Truncate(ip, 40))
	}
	c := netutil.Client(netutil.Any, lookupTimeout)
	defer c.CloseIdleConnections()
	url := ipAPIByIP + parsed.String() + "?fields=status,message,country,countryCode,regionName,city,isp,org,as,query"
	resp, err := netutil.Get(ctx, c, url, 1<<16, nil)
	if err != nil {
		return nil, err
	}
	var v struct {
		Status     string `json:"status"`
		Message    string `json:"message"`
		Query      string `json:"query"`
		Country    string `json:"country"`
		CC         string `json:"countryCode"`
		RegionName string `json:"regionName"`
		City       string `json:"city"`
		ISP        string `json:"isp"`
		Org        string `json:"org"`
		AS         string `json:"as"`
	}
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return nil, err
	}
	if v.Status != "success" {
		return nil, fmt.Errorf("ip-api: %s", v.Message)
	}
	asn, asName := splitAS(v.AS)
	return &report.Geo{
		IP: v.Query, ASN: asn, ASName: asName, Org: v.Org, ISP: v.ISP,
		Country: v.Country, CountryCode: v.CC, Region: v.RegionName, City: v.City,
		Source: "ip-api.com",
	}, nil
}
