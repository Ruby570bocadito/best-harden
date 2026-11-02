package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/remediate"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

const sample = `# Laboratorio de Adarve · ubuntu-24.04
# Imagen: ubuntu24 20261026.1

LNX-A-001  pass
LNX-A-002  fail   PASS_MAX_DAYS: actual «99999» · esperado «<= 365»
LNX-A-003  pass|fail  apt: 3 pendientes  # cambia con las actualizaciones publicadas
`

func mustGolden(t *testing.T, s string) *golden {
	t.Helper()
	g, err := parseGolden(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func obs(m map[string]engine.Status) *observation {
	o := &observation{byID: map[string]observed{}, host: "Ubuntu 24.04 · 6.8", profiles: []string{"linux-server-l2"}}
	for id, st := range m {
		o.byID[id] = observed{status: st}
	}
	return o
}

func TestParseGolden(t *testing.T) {
	g := mustGolden(t, sample)
	if g.image != "ubuntu24 20261026.1" || len(g.byID) != 3 {
		t.Fatalf("imagen %q, %d controles", g.image, len(g.byID))
	}
	if v := g.volatile(); !v["LNX-A-003"] || v["LNX-A-001"] {
		t.Errorf("volátiles: %v", v)
	}
	for name, bad := range map[string]string{
		"repetido":          "X-1 pass\nX-1 fail\n",
		"error aceptado":    "X-1 error\n",
		"sin evaluar":       "X-1 skipped\n",
		"varios sin motivo": "X-1 pass|fail\n",
		"sin estado":        "X-1\n",
		"marca de revisión": "X-1 fail  algo  # REVISAR: control nuevo\n",
	} {
		if _, err := parseGolden(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: se aceptó %q", name, bad)
		}
	}
}

func TestCompare(t *testing.T) {
	g := mustGolden(t, sample)
	if p := compare(g, obs(map[string]engine.Status{"LNX-A-001": engine.Pass, "LNX-A-002": engine.Fail, "LNX-A-003": engine.Fail})); len(p) != 0 {
		t.Fatalf("diferencias inesperadas: %v", p)
	}
	p := compare(g, obs(map[string]engine.Status{"LNX-A-001": engine.Fail, "LNX-A-003": engine.Error, "LNX-A-004": engine.NA}))
	want := []string{"LNX-A-001 esperado pass, obtenido fail", "LNX-A-003 error en una imagen limpia",
		"LNX-A-004 no tiene resultado esperado", "LNX-A-002 ya no se evalúa"}
	if len(p) != len(want) {
		t.Fatalf("diferencias: %q", p)
	}
	for i := range want {
		if !strings.HasPrefix(norm(p[i]), want[i]) {
			t.Errorf("diferencia %d: %q, quiero que empiece por %q", i, p[i], want[i])
		}
	}
}

// norm junta los espacios: las columnas de los mensajes van alineadas.
func norm(s string) string { return strings.Join(strings.Fields(s), " ") }

func TestPropose(t *testing.T) {
	g := mustGolden(t, sample)
	o := obs(map[string]engine.Status{"LNX-A-001": engine.Fail, "LNX-A-002": engine.Fail, "LNX-A-003": engine.Pass, "LNX-A-004": engine.NA})
	o.byID["LNX-A-001"] = observed{status: engine.Fail, detail: "PermitRootLogin: actual «yes» · esperado «no»"}
	p := propose("ubuntu-24.04", "ubuntu24 20261102.1", g, o)
	for _, s := range []string{
		"# Imagen: ubuntu24 20261102.1",
		"LNX-A-001  fail    PermitRootLogin: actual «yes» · esperado «no»  # REVISAR: antes pass",
		"LNX-A-002  fail   PASS_MAX_DAYS: actual «99999» · esperado «<= 365»\n", // la línea revisada, tal cual
		"LNX-A-003  pass|fail  apt: 3 pendientes  # cambia",
		"LNX-A-004  na  # REVISAR: control nuevo",
	} {
		if !strings.Contains(p, s) {
			t.Errorf("falta %q en la propuesta:\n%s", s, p)
		}
	}
	// La primera propuesta no lleva marcas y se lee como fichero esperado.
	first := propose("ubuntu-24.04", "", nil, o)
	if strings.Contains(first, reviewMark) {
		t.Errorf("la primera propuesta lleva marcas:\n%s", first)
	}
	if g2 := mustGolden(t, first); len(compare(g2, o)) != 0 {
		t.Errorf("la propuesta no coincide con lo observado:\n%s", first)
	}
}

func TestAnnotate(t *testing.T) {
	text := strings.Repeat("LNX-A-001  fail  actual «50%» · esperado «0»\n", 200)
	parts := chunks(text, 3800)
	if len(parts) < 3 || strings.Join(parts, "") != text {
		t.Fatalf("%d trozos; se pierde texto: %v", len(parts), strings.Join(parts, "") != text)
	}
	for _, p := range parts {
		if len(p) > 3800 || !strings.HasSuffix(p, "\n") {
			t.Errorf("trozo de %d bytes o partido a mitad de línea", len(p))
		}
	}
	var b strings.Builder
	t.Setenv("GITHUB_ACTIONS", "true")
	annotate(&b, "notice", "Propuesta para a: b, c", "uno\ndos 100%\n")
	if got := b.String(); got != "::notice title=Propuesta para a%3A b%2C c::uno%0Ados 100%25%0A\n" {
		t.Errorf("anotación %q", got)
	}
	b.Reset()
	annotate(&b, "notice", "x", text)
	if n := strings.Count(b.String(), "::notice title=x ("); n != len(parts) || !strings.Contains(b.String(), "(1/") {
		t.Errorf("%d anotaciones para %d trozos", n, len(parts))
	}
}

func writeReport(t *testing.T, dir, profile string, res map[string]engine.Eval) string {
	t.Helper()
	rep := engine.Report{Schema: engine.SchemaVersion, Profile: &rule.Profile{ID: profile}}
	for id, e := range res {
		rep.Results = append(rep.Results, engine.Result{Rule: &rule.Rule{ID: id}, Eval: e})
	}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, profile+".json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadReportsMergesProfiles(t *testing.T) {
	dir := t.TempDir()
	composite := engine.Eval{Status: engine.Fail, Children: []engine.Eval{
		{Status: engine.Pass, Field: "A"},
		{Status: engine.Fail, Field: "MinimumPasswordLength", Actual: "0", Expected: ">= 14"},
	}}
	a := writeReport(t, dir, "win-server-l2", map[string]engine.Eval{"W-1": composite, "W-2": {Status: engine.Pass}})
	b := writeReport(t, dir, "win-workstation-l2", map[string]engine.Eval{"W-2": {Status: engine.Fail}, "W-3": {Status: engine.NA, Message: "sin BitLocker"}})
	o, problems, err := readReports([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(o.byID) != 3 || strings.Join(o.profiles, ",") != "win-server-l2,win-workstation-l2" {
		t.Fatalf("%d controles, perfiles %v", len(o.byID), o.profiles)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "W-2") {
		t.Errorf("la discrepancia entre perfiles no se detectó: %v", problems)
	}
	if d := o.byID["W-1"].detail; d != "actual «0» · esperado «>= 14» · MinimumPasswordLength" {
		t.Errorf("evidencia del fallo: %q", d)
	}
	if d := o.byID["W-3"].detail; d != "sin BitLocker" {
		t.Errorf("motivo de no aplica: %q", d)
	}
}

func TestCycle(t *testing.T) {
	before := obs(map[string]engine.Status{"A": engine.Fail, "B": engine.Pass, "C": engine.Fail, "V": engine.Fail})
	after := obs(map[string]engine.Status{"A": engine.Pass, "B": engine.Pass, "C": engine.Fail, "V": engine.Pass})
	restored := obs(map[string]engine.Status{"A": engine.Fail, "B": engine.Pass, "C": engine.Fail, "V": engine.Pass})
	m := &remediate.Manifest{ID: "x", Status: remediate.StatusRolledBack, Rules: []remediate.RuleOutcome{{RuleID: "A", Outcome: remediate.OutcomeVerified}}}
	vol := map[string]bool{"V": true}
	if p, n := cycleProblems(vol, before, after, restored, m); len(p) != 0 || n != 1 {
		t.Fatalf("ciclo limpio con problemas: %v (%d verificados)", p, n)
	}

	after.byID["B"] = observed{status: engine.Fail, detail: "roto"}
	restored.byID["C"] = observed{status: engine.Pass}
	m.Status = remediate.StatusPartial
	m.Rules = append(m.Rules, remediate.RuleOutcome{RuleID: "C", Outcome: remediate.OutcomeNotEffective, Message: "sigue fallando"})
	p, _ := cycleProblems(vol, before, after, restored, m)
	for _, s := range []string{"C harden: not-effective · sigue fallando", "B pasaba y tras harden da fail · roto",
		"C el rollback no lo deja como estaba: antes fail, después pass", "quedó como \"partial\""} {
		found := false
		for _, x := range p {
			found = found || strings.Contains(norm(x), s)
		}
		if !found {
			t.Errorf("falta %q en %q", s, p)
		}
	}
	if p, _ := cycleProblems(nil, before, after, restored, &remediate.Manifest{Status: remediate.StatusRolledBack}); !strings.Contains(strings.Join(p, "\n"), "no reparó ningún control") {
		t.Errorf("un ciclo sin reparaciones no se detectó: %v", p)
	}
}
