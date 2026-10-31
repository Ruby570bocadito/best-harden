package engine

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/exceptions"
	"github.com/Ruby570bocadito/adarve/internal/probes"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		op       string
		actual   any
		expected any
		want     bool
	}{
		{"eq", "2", 2, true},
		{"eq", uint64(0), 0, true},
		{"eq", "No", "no", true},
		{"eq", true, "True", true},
		{"eq", "False", false, true},
		{"ne", "yes", "no", true},
		{"gte", "14", 14, true},
		{"gte", int64(8), 14, false},
		{"lte", "4", 4, true},
		{"between", 5, []any{1, 5}, true},
		{"between", 0, []any{1, 5}, false},
		{"in", "prohibit-password", []any{"no", "prohibit-password"}, true},
		{"not_in", "enabled", []any{"enabled", "enabled-runtime"}, false},
		{"contains", []any{"rw", "nosuid", "nodev"}, []any{"nodev", "nosuid"}, true},
		{"contains", []any{"rw", "nosuid"}, []any{"nodev", "nosuid"}, false},
		{"contains", []any{1, 2}, 1, true},
		{"not_contains", "aes128-ctr,aes256-cbc", "3des", true},
		{"regex", "aes256-cbc", "cbc", true},
		{"not_regex", "aes256-ctr,chacha20", "(cbc|3des|arcfour)", true},
		{"bits_set", uint64(2147483640), 24, true},
		{"bits_clear", uint64(2147483640), 7, true},
		{"bits_clear", uint64(2147483647), 7, false},
		{"mode_max", "0644", "0600", false},
		{"mode_max", "0600", "0644", true},
		{"mode_max", "0640", "0640", true},
	}
	for _, c := range cases {
		got, err := compare(c.op, c.actual, c.expected)
		if err != nil {
			t.Errorf("%s(%v, %v): error %v", c.op, c.actual, c.expected, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s(%v, %v) = %v, quiero %v", c.op, c.actual, c.expected, got, c.want)
		}
	}
}

func TestCompareErrors(t *testing.T) {
	if _, err := compare("gte", "abc", 3); err == nil {
		t.Error("gte con texto no numérico debería fallar")
	}
	if _, err := compare("regex", "x", "("); err == nil {
		t.Error("regex inválida debería fallar")
	}
}

func TestLookupField(t *testing.T) {
	f := map[string]any{"Domain": map[string]any{"Enabled": "True"}, "a.b": 1}
	if v, ok := lookupField(f, "Domain.Enabled"); !ok || v != "True" {
		t.Errorf("Domain.Enabled = %v, %v", v, ok)
	}
	if v, ok := lookupField(f, "domain.enabled"); !ok || v != "True" {
		t.Errorf("búsqueda sin mayúsculas falló: %v, %v", v, ok)
	}
	if v, ok := lookupField(f, "a.b"); !ok || v != 1 {
		t.Errorf("clave literal con punto: %v, %v", v, ok)
	}
	if _, ok := lookupField(f, "Private.Enabled"); ok {
		t.Error("campo inexistente encontrado")
	}
}

// fakeProbe devuelve observaciones fijas por clave.
type fakeProbe struct{}

func (fakeProbe) Name() string         { return "fake" }
func (fakeProbe) DefaultField() string { return "value" }
func (fakeProbe) Collect(_ context.Context, p probes.Params) (probes.Observation, error) {
	switch p.String("key") {
	case "missing":
		return probes.Observation{Found: false}, nil
	case "na":
		return probes.Observation{}, probes.NotApplicable("no aplica")
	case "list":
		return probes.Observation{Found: true, Fields: map[string]any{"value": []any{uint64(2), uint64(2)}}}, nil
	case "netbios":
		return probes.Observation{Found: true, Fields: map[string]any{"value": []any{uint64(0), uint64(0), uint64(2), uint64(0)}}}, nil
	case "priv":
		return probes.Observation{}, probes.NeedsPrivilege("solo como administrador")
	case "denied":
		return probes.Observation{}, &fs.PathError{Op: "open", Path: "/etc/shadow", Err: fs.ErrPermission}
	}
	return probes.Observation{Found: true, Fields: map[string]any{"value": p.String("key")}}, nil
}

func init() { probes.Register(fakeProbe{}) }

func leaf(key, op string, exp any) rule.Check {
	return rule.Check{Probe: "fake", Op: op, Expected: exp, Params: map[string]any{"key": key}}
}

func TestEvalLeafMissing(t *testing.T) {
	e := New()
	ctx := probes.WithSession(context.Background(), probes.NewSession())

	c := leaf("missing", "eq", 0)
	if ev := e.evalCheck(ctx, c); ev.Status != Fail {
		t.Errorf("ausente sin default debería fallar, es %s", ev.Status)
	}
	c.HasDefault, c.Default = true, 0
	if ev := e.evalCheck(ctx, c); ev.Status != Pass {
		t.Errorf("ausente con default 0 debería pasar, es %s (%s)", ev.Status, ev.Message)
	}
	c = leaf("missing", "eq", 0)
	c.OnMissing = "na"
	if ev := e.evalCheck(ctx, c); ev.Status != NA {
		t.Errorf("on_missing na → %s", ev.Status)
	}
	if ev := e.evalCheck(ctx, leaf("na", "eq", 1)); ev.Status != NA {
		t.Errorf("NotApplicable → %s", ev.Status)
	}
	if ev := e.evalCheck(ctx, leaf("missing", "absent", nil)); ev.Status != Pass {
		t.Errorf("absent → %s", ev.Status)
	}
}

func TestEvalEach(t *testing.T) {
	e := New()
	ctx := probes.WithSession(context.Background(), probes.NewSession())
	c := leaf("list", "eq", 2)
	c.Each = "all"
	if ev := e.evalCheck(ctx, c); ev.Status != Pass {
		t.Errorf("each all → %s (%s)", ev.Status, ev.Message)
	}
}

func TestEvalEachEvidence(t *testing.T) {
	e := New()
	ctx := probes.WithSession(context.Background(), probes.NewSession())
	c := leaf("netbios", "eq", 2)
	c.Each = "all"
	ev := e.evalCheck(ctx, c)
	if ev.Status != Fail || ev.Actual != "0 ×3, 2 (cumplen 1 de 4)" {
		t.Errorf("each all → %s %q", ev.Status, ev.Actual)
	}
}

func TestEvalPrivilege(t *testing.T) {
	old := probes.Privileged
	t.Cleanup(func() { probes.Privileged = old })
	e := New()
	ctx := probes.WithSession(context.Background(), probes.NewSession())

	probes.Privileged = func() bool { return false }
	if ev := e.evalCheck(ctx, leaf("priv", "eq", 1)); ev.Status != Skipped || ev.Message != "solo como administrador" {
		t.Errorf("PrivilegeError → %s %q", ev.Status, ev.Message)
	}
	if ev := e.evalCheck(ctx, leaf("denied", "eq", 1)); ev.Status != Skipped || !strings.Contains(ev.Message, "/etc/shadow") {
		t.Errorf("permiso denegado sin privilegios → %s %q", ev.Status, ev.Message)
	}
	// Con privilegios, un permiso denegado (SELinux, ACL rara) es un error real.
	probes.Privileged = func() bool { return true }
	if ev := e.evalCheck(ctx, leaf("denied", "eq", 1)); ev.Status != Error {
		t.Errorf("permiso denegado con privilegios → %s", ev.Status)
	}
	probes.Privileged = func() bool { return false }

	// Compuestas: un fallo manda; sin fallos, lo no evaluado impide dar el control por bueno.
	if ev := e.evalCheck(ctx, rule.Check{All: []rule.Check{leaf("a", "eq", "a"), leaf("priv", "eq", 1)}}); ev.Status != Skipped {
		t.Errorf("all pass + skipped → %s", ev.Status)
	}
	if ev := e.evalCheck(ctx, rule.Check{All: []rule.Check{leaf("a", "eq", "x"), leaf("priv", "eq", 1)}}); ev.Status != Fail {
		t.Errorf("all fail + skipped → %s", ev.Status)
	}
	if ev := e.evalCheck(ctx, rule.Check{Any: []rule.Check{leaf("priv", "eq", 1), leaf("b", "eq", "b")}}); ev.Status != Pass {
		t.Errorf("any skipped + pass → %s", ev.Status)
	}

	// No cuenta en la puntuación, pero la marca como parcial.
	r1 := &rule.Rule{ID: "T-X-1", Severity: rule.SevHigh, Category: "A"}
	r2 := &rule.Rule{ID: "T-X-2", Severity: rule.SevCritical, Category: "A"}
	s := ComputeScore([]Result{{Rule: r1, Eval: Eval{Status: Pass}}, {Rule: r2, Eval: Eval{Status: Skipped}}})
	if s.Value != 100 || s.Skipped != 1 || !s.Partial {
		t.Errorf("puntuación con no evaluados: %+v", s)
	}
}

func TestEvalComposite(t *testing.T) {
	e := New()
	ctx := probes.WithSession(context.Background(), probes.NewSession())
	all := rule.Check{All: []rule.Check{leaf("a", "eq", "a"), leaf("b", "eq", "x")}}
	if ev := e.evalCheck(ctx, all); ev.Status != Fail {
		t.Errorf("all con un fallo → %s", ev.Status)
	}
	anyC := rule.Check{Any: []rule.Check{leaf("a", "eq", "x"), leaf("b", "eq", "b")}}
	if ev := e.evalCheck(ctx, anyC); ev.Status != Pass {
		t.Errorf("any con un acierto → %s", ev.Status)
	}
	allNA := rule.Check{All: []rule.Check{leaf("na", "eq", 1), leaf("na", "eq", 1)}}
	if ev := e.evalCheck(ctx, allNA); ev.Status != NA {
		t.Errorf("all de NA → %s", ev.Status)
	}
	mixed := rule.Check{All: []rule.Check{leaf("a", "eq", "a"), leaf("na", "eq", 1)}}
	if ev := e.evalCheck(ctx, mixed); ev.Status != Pass {
		t.Errorf("all pass + NA → %s", ev.Status)
	}
}

func TestScore(t *testing.T) {
	crit := &rule.Rule{ID: "T-X-1", Severity: rule.SevCritical, Category: "A"}
	low := &rule.Rule{ID: "T-X-2", Severity: rule.SevLow, Category: "B"}
	na := &rule.Rule{ID: "T-X-3", Severity: rule.SevHigh, Category: "B"}
	s := ComputeScore([]Result{
		{Rule: crit, Eval: Eval{Status: Pass}},
		{Rule: low, Eval: Eval{Status: Fail}},
		{Rule: na, Eval: Eval{Status: NA}},
	})
	if s.Value != 91 { // 10 / 11
		t.Errorf("score = %d, quiero 91", s.Value)
	}
	if s.Grade != "A" || s.Passed != 1 || s.Failed != 1 || s.NA != 1 {
		t.Errorf("score inesperado: %+v", s)
	}
	if !s.Scored {
		t.Error("con controles evaluados la puntuación existe")
	}
	// Sin nada superado ni fallido no hay puntuación (antes salía 100/A).
	empty := ComputeScore([]Result{{Rule: na, Eval: Eval{Status: Skipped}}})
	if empty.Scored || empty.Value != 0 || empty.Grade != "N/A" || !empty.Partial {
		t.Errorf("sin controles evaluables: %+v", empty)
	}
	for _, c := range empty.ByCategory {
		if c.Scored {
			t.Errorf("categoría sin evaluar con puntuación: %+v", c)
		}
	}
}

// En "any", un hijo con error y otro fallido da error (el que no se pudo
// evaluar quizá cumplía), no un fallo.
func TestEvalAnyErrorBeforeFail(t *testing.T) {
	e := New()
	ctx := probes.WithSession(context.Background(), probes.NewSession())
	c := rule.Check{Any: []rule.Check{leaf("a", "regex", "("), leaf("b", "eq", "x")}}
	if ev := e.evalCheck(ctx, c); ev.Status != Error {
		t.Errorf("any con error + fallo → %s, quiero error", ev.Status)
	}
	c = rule.Check{Any: []rule.Check{leaf("a", "regex", "("), leaf("b", "eq", "b")}}
	if ev := e.evalCheck(ctx, c); ev.Status != Pass {
		t.Errorf("any con error + acierto → %s, quiero pass", ev.Status)
	}
}

func TestRequires(t *testing.T) {
	r := &rule.Rule{ID: "T-X-9", Severity: rule.SevHigh, Category: "x", Requires: []string{"windows-joined"},
		Check: leaf("a", "eq", "a")}
	e := New()
	e.HostTags = []string{"windows-client", "windows"}
	if res := e.Run(context.Background(), []*rule.Rule{r}, nil); res[0].Status != NA || res[0].Message == "" {
		t.Errorf("equipo no unido: %s %q", res[0].Status, res[0].Message)
	}
	e.HostTags = append(e.HostTags, "windows-joined")
	if res := e.Run(context.Background(), []*rule.Rule{r}, nil); res[0].Status != Pass {
		t.Errorf("equipo unido: %s", res[0].Status)
	}
}

func TestApplyExceptions(t *testing.T) {
	r1 := &rule.Rule{ID: "WIN-SYS-003", Severity: rule.SevHigh, Category: "A"}
	r2 := &rule.Rule{ID: "WIN-NET-006", Severity: rule.SevHigh, Category: "A"}
	r3 := &rule.Rule{ID: "LNX-FW-001", Severity: rule.SevHigh, Category: "A"}
	r4 := &rule.Rule{ID: "WIN-SYS-004", Severity: rule.SevHigh, Category: "A"}
	results := []Result{
		{Rule: r1, Eval: Eval{Status: Fail}},
		{Rule: r2, Eval: Eval{Status: Fail}},
		{Rule: r3, Eval: Eval{Status: Fail}},
		{Rule: r4, Eval: Eval{Status: Pass}},
	}
	reason := "riesgo aceptado por el comité de seguridad"
	f := &exceptions.File{Exceptions: []exceptions.Entry{
		{Rule: "WIN-SYS-003", Reason: reason, Created: "2026-10-01", Expires: "2027-01-31"},
		{Rule: "LNX-FW-001", Reason: reason, Created: "2026-01-01", Expires: "2026-06-30"},
		{Rule: "WIN-SYS-004", Reason: reason, Created: "2026-10-01", Expires: "2027-01-31"},
	}}
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.Local)
	expired := ApplyExceptions(results, f, "PC-01", now)
	byID := map[string]Result{}
	for _, r := range results {
		byID[r.Rule.ID] = r
	}
	if r := byID["WIN-SYS-003"]; r.Status != Exception || r.Exception == nil || r.Exception.Expired {
		t.Errorf("vigente → %s %+v", r.Status, r.Exception)
	}
	if r := byID["LNX-FW-001"]; r.Status != Fail || r.Exception == nil || !r.Exception.Expired {
		t.Errorf("caducada → %s %+v", r.Status, r.Exception)
	}
	if len(expired) != 1 || expired[0].Rule.ID != "LNX-FW-001" {
		t.Errorf("caducadas devueltas: %v", expired)
	}
	if r := byID["WIN-SYS-004"]; r.Status != Pass || r.Exception != nil {
		t.Errorf("un control que pasa no cambia: %s %+v", r.Status, r.Exception)
	}
	if r := byID["WIN-NET-006"]; r.Status != Fail {
		t.Errorf("sin excepción → %s", r.Status)
	}
	// Orden: fallidos primero, luego la excepción, luego los superados.
	if results[0].Status != Fail || results[2].Status != Exception || results[3].Status != Pass {
		t.Errorf("orden tras aplicar: %s %s %s %s", results[0].Status, results[1].Status, results[2].Status, results[3].Status)
	}
	s := ComputeScore(results)
	if s.Exceptions != 1 || s.Failed != 2 || s.Value != 33 { // 5 / (5+5+5)
		t.Errorf("puntuación con excepciones: %+v", s)
	}
}
