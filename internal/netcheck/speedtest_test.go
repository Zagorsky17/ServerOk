package netcheck

// speedtest_test.go — разбор значения флага -nodes и имени способа замера.
// Проверяется именно то, что видит пользователь: смешивание наборов,
// повторы и опечатки. Сами измерения тестами не покрываются — они ходят в
// сеть.

import (
	"strings"
	"testing"

	"github.com/Zagorsky17/ServerOk/internal/report"
)

func TestResolveSet(t *testing.T) {
	cases := []struct {
		in    string
		first string
		count int
	}{
		{"", "Speedtest.net", len(defaultSet)},
		{"fast", "Speedtest.net", len(fastSet)},
		{"eu", "London, UK", len(euSet)},
		{"EUROPE", "London, UK", len(euSet)},
		{"us", "Los Angeles, US", len(usSet)},
		{"asia", "Hong Kong", len(asiaSet)},
	}
	for _, c := range cases {
		nodes, err := resolveSet(c.in)
		if err != nil {
			t.Fatalf("resolveSet(%q): %v", c.in, err)
		}
		if len(nodes) != c.count || nodes[0].Label != c.first {
			t.Errorf("resolveSet(%q) = %d nodes starting with %q, want %d starting with %q",
				c.in, len(nodes), nodes[0].Label, c.count, c.first)
		}
	}
}

func TestResolveSetCombines(t *testing.T) {
	nodes, err := resolveSet("eu, asia, 12345")
	if err != nil {
		t.Fatalf("resolveSet: %v", err)
	}
	if want := len(euSet) + len(asiaSet) + 1; len(nodes) != want {
		t.Fatalf("got %d nodes, want %d", len(nodes), want)
	}
	last := nodes[len(nodes)-1]
	if last.Search != "12345" || last.Label != "Server 12345" {
		t.Errorf("numeric ID should become a node of its own: %+v", last)
	}
}

func TestResolveSetDeduplicates(t *testing.T) {
	// Наборы пересекаются (Токио есть и в default, и в asia) — город не
	// должен меряться дважды.
	nodes, err := resolveSet("default,asia,europe,eu")
	if err != nil {
		t.Fatalf("resolveSet: %v", err)
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		if seen[n.Label] {
			t.Errorf("node %q appears twice", n.Label)
		}
		seen[n.Label] = true
	}
}

func TestResolveSetRejectsUnknown(t *testing.T) {
	if _, err := resolveSet("eu,mars"); err == nil {
		t.Fatal("unknown set name should be an error, not a silent skip")
	} else if !strings.Contains(err.Error(), "mars") {
		t.Errorf("error should name the offending part: %v", err)
	}
}

func TestValidateSet(t *testing.T) {
	if err := ValidateSet("us,eu"); err != nil {
		t.Errorf("us,eu should be valid: %v", err)
	}
	if err := ValidateSet("nowhere"); err == nil {
		t.Error("nowhere should be rejected")
	}
}

func TestNormalizeMethod(t *testing.T) {
	cases := map[string]string{
		"":              report.MethodOokla,
		"ookla":         report.MethodOokla,
		"Speedtest.net": report.MethodOokla,
		" Cloudflare  ": report.MethodCloudflare,
		"cf":            report.MethodCloudflare,
		"fast.com":      "",
	}
	for in, want := range cases {
		if got := NormalizeMethod(in); got != want {
			t.Errorf("NormalizeMethod(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPrefixPicker проверяет отбор живых кандидатов: он обязан сохранять
// исходный приоритет независимо от того, в каком порядке ответили пробы, —
// именно это отличает «лучший сервер» от «первого ответившего».
func TestPrefixPicker(t *testing.T) {
	cases := []struct {
		name  string
		alive []bool // кто отвечает, в исходном порядке кандидатов
		order []int  // в каком порядке приходят результаты проб
		want  int
		out   []int
	}{
		{"все живы, берём первых двух", []bool{true, true, true}, []int{0, 1, 2}, 2, []int{0, 1}},
		{"ответы пришли задом наперёд", []bool{true, true, true}, []int{2, 1, 0}, 2, []int{0, 1}},
		{"быстрый мёртвый не вытесняет медленного живого",
			[]bool{false, true, true}, []int{0, 2, 1}, 2, []int{1, 2}},
		{"живых меньше, чем нужно", []bool{false, true, false}, []int{1, 0, 2}, 3, []int{1}},
		{"живых нет", []bool{false, false}, []int{0, 1}, 2, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newPrefixPicker(len(c.alive), c.want)
			for _, idx := range c.order {
				if p.full() {
					break
				}
				p.mark(idx, c.alive[idx])
			}
			if len(p.chosen) != len(c.out) {
				t.Fatalf("chosen = %v, want %v", p.chosen, c.out)
			}
			for i, v := range c.out {
				if p.chosen[i] != v {
					t.Fatalf("chosen = %v, want %v", p.chosen, c.out)
				}
			}
		})
	}
}

// TestPrefixPickerStopsEarly фиксирует смысл раннего выхода: как только
// нужное количество набрано, оставшиеся пробы можно не ждать.
func TestPrefixPickerStopsEarly(t *testing.T) {
	p := newPrefixPicker(6, 2)
	p.mark(0, true)
	p.mark(1, true)
	if !p.full() {
		t.Fatalf("picker should be full after two alive candidates, chosen = %v", p.chosen)
	}
}
