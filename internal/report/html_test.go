package report

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/platform"
	"github.com/Ruby570bocadito/adarve/internal/surface"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// Un valor leído del sistema auditado (p. ej. una línea de sudoers) no debe
// poder romper la etiqueta <script> ni inyectar HTML en el informe.
func TestHTMLNeutralizesHostileData(t *testing.T) {
	hostile := `</script><script>alert(1)</script><img src=x onerror=alert(2)>`
	rep := &engine.Report{
		Schema: engine.SchemaVersion,
		Results: []engine.Result{{
			Rule: &rule.Rule{ID: "T-X-001", Title: hostile, Severity: rule.SevHigh, Category: "x"},
			Eval: engine.Eval{Status: engine.Fail, Actual: hostile},
		}},
	}
	var buf bytes.Buffer
	if err := HTML(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert") || strings.Contains(out, "<img src=x") {
		t.Fatal("el informe contiene HTML sin escapar procedente de los datos")
	}
	if strings.Contains(out, "__ADARVE_DATA__") || strings.Contains(out, "__NONCE__") {
		t.Fatal("quedan marcadores sin sustituir")
	}
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]{16,})'`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, `<script nonce="`+m[1]+`">`) {
		t.Fatal("la CSP y el script no comparten un nonce válido")
	}
	var buf2 bytes.Buffer
	_ = HTML(&buf2, rep)
	if m2 := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(buf2.String()); m2 == nil || m2[1] == m[1] {
		t.Fatal("el nonce debe ser aleatorio en cada informe")
	}
}

func TestFocusLeaf(t *testing.T) {
	ev := engine.Eval{Status: engine.Fail, Children: []engine.Eval{
		{Status: engine.Pass, Label: "a"},
		{Status: engine.Fail, Children: []engine.Eval{{Status: engine.Fail, Label: "b", Actual: "1"}}},
	}}
	if l := FocusLeaf(ev); l.Label != "b" || l.Actual != "1" {
		t.Errorf("FocusLeaf = %+v", l)
	}
}

func TestSavedReports(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	for i, v := range []int{40, 65, 88} {
		rep := &engine.Report{Schema: engine.SchemaVersion, FinishedAt: base.Add(time.Duration(i) * time.Hour),
			Host: platform.Info{Hostname: "pc-01"}, Score: engine.Score{Value: v, Grade: "X"}}
		if _, _, err := Save(dir, rep, 30); err != nil {
			t.Fatal(err)
		}
	}
	other := &engine.Report{FinishedAt: base, Host: platform.Info{Hostname: "otro"}}
	if _, _, err := Save(dir, other, 30); err != nil {
		t.Fatal(err)
	}
	list, err := ListSaved(dir, "PC-01")
	if err != nil || len(list) != 3 {
		t.Fatalf("ListSaved: %v %d", err, len(list))
	}
	if list[0].Score.Value != 40 || list[2].Score.Value != 88 {
		t.Errorf("orden cronológico: %d → %d", list[0].Score.Value, list[2].Score.Value)
	}
	rep, err := LoadSaved(dir, list[2].ID)
	if err != nil || rep.Score.Value != 88 {
		t.Errorf("LoadSaved: %v %+v", err, rep)
	}
	for _, bad := range []string{"../etc/passwd", "adarve-x-20261015-100000/../../a", "x.json", ""} {
		if _, err := LoadSaved(dir, bad); err == nil {
			t.Errorf("%q debería rechazarse", bad)
		}
	}
}

func TestTableIgnoresColorCodes(t *testing.T) {
	red := func(s string) string { return "\x1b[31m" + s + "\x1b[0m" }
	var tb Table
	tb.Row(Styled("PUERTO", red), "PROCESO")
	tb.Row("22/tcp", Styled("sshd", red))
	tb.Row("27036/udp", "steam.exe")
	var b bytes.Buffer
	tb.Write(&b)
	plain := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(b.String(), "")
	want := "PUERTO     PROCESO\n22/tcp     sshd\n27036/udp  steam.exe\n"
	if plain != want {
		t.Errorf("tabla:\n%q\nquiero:\n%q", plain, want)
	}
}

// El informe de superficie muestra nombres de procesos, reglas y recursos
// compartidos del equipo: tampoco pueden inyectar HTML.
func TestSurfaceHTMLNeutralizesHostileData(t *testing.T) {
	hostile := `</script><script>alert(1)</script><img src=x onerror=alert(2)>`
	rep := &surface.Report{Schema: surface.Schema, Score: 72, Grade: "C", Exposed: 1, Reachable: 1,
		Ports: []surface.Port{{Proto: "tcp", Port: 8080, Addresses: []string{"0.0.0.0"}, Scope: surface.ScopeNetwork, Process: hostile,
			Firewall: surface.FirewallOpen, FirewallWhy: "lo permite la regla «" + hostile + "»"}},
		Findings:  []surface.Finding{{ID: "SURF-APPS-OPEN", Severity: rule.SevLow, Title: hostile, Subject: "8080/tcp", FirewallRules: []string{hostile}}},
		Inventory: surface.Inventory{Shares: []surface.Share{{Kind: "smb", Name: hostile}}, Firewall: &surface.Firewall{Profiles: []surface.FirewallProfile{}}},
	}
	var buf bytes.Buffer
	if err := SurfaceHTML(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert") || strings.Contains(out, "<img src=x") {
		t.Fatal("el informe contiene HTML sin escapar procedente de los datos")
	}
	for _, mark := range []string{"__ADARVE_DATA__", "__NONCE__", "__STYLE__"} {
		if strings.Contains(out, mark) {
			t.Fatalf("queda el marcador %s", mark)
		}
	}
	if !strings.Contains(out, "--page:") || !strings.Contains(out, ".ptable") {
		t.Error("faltan los estilos compartidos o los propios")
	}
	m := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9_-]{16,})'`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, `<script nonce="`+m[1]+`">`) {
		t.Fatal("la CSP y el script no comparten un nonce válido")
	}
	if strings.Contains(out, "innerHTML") || strings.Contains(out, "insertAdjacentHTML") {
		t.Error("el informe no debe insertar HTML")
	}
}

func TestSurfaceHistoryAndChanges(t *testing.T) {
	dir := t.TempDir()
	mk := func(ts time.Time, ports ...surface.Port) *surface.Report {
		return &surface.Report{Schema: surface.Schema, Host: platform.Info{Hostname: "Rby"}, FinishedAt: ts, Score: 80, Grade: "B", Ports: ports}
	}
	p22 := surface.Port{Proto: "tcp", Port: 22, Addresses: []string{"0.0.0.0"}, Scope: surface.ScopeNetwork, Process: "sshd", Firewall: surface.FirewallOpen}
	p8766 := surface.Port{Proto: "tcp", Port: 8766, Addresses: []string{"0.0.0.0"}, Scope: surface.ScopeNetwork, Process: "AutoClaw.exe", Firewall: surface.FirewallOpen}
	t0 := time.Date(2026, 10, 15, 9, 0, 0, 0, time.Local)
	if prev, err := LatestSurface(dir, "Rby"); prev != nil || err != nil {
		t.Fatalf("sin historial: %v %v", prev, err)
	}
	for i, r := range []*surface.Report{mk(t0, p22), mk(t0.Add(time.Hour), p22), mk(t0.Add(2*time.Hour), p22)} {
		if _, _, err := SaveSurface(dir, r, 2); err != nil {
			t.Fatalf("guardar %d: %v", i, err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "surface-Rby-*.json"))
	if len(files) != 2 {
		t.Errorf("se conservan 2 análisis, hay %d", len(files))
	}
	prev, err := LatestSurface(dir, "Rby")
	if err != nil || prev == nil || !prev.FinishedAt.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("último análisis: %v %v", prev, err)
	}
	cur := mk(t0.Add(3*time.Hour), p22, p8766)
	cur.Changes = surface.Diff(prev, cur)
	var buf bytes.Buffer
	SurfaceConsole(&buf, cur, false, Style{})
	out := buf.String()
	if !strings.Contains(out, "CAMBIOS DESDE EL 15/10/2026 11:00") || !strings.Contains(out, "+ 8766/tcp (AutoClaw.exe) escucha en la red: abierto a cualquiera") {
		t.Errorf("la consola debe mostrar los cambios:\n%s", out)
	}
	cur.Changes = surface.Diff(cur, cur)
	buf.Reset()
	SurfaceConsole(&buf, cur, false, Style{})
	if !strings.Contains(buf.String(), "Sin cambios en la exposición desde el") {
		t.Errorf("sin cambios:\n%s", buf.String())
	}
}

func TestScanChangesConsole(t *testing.T) {
	rep := &engine.Report{Schema: engine.SchemaVersion, Score: engine.Score{Value: 70, Grade: "C"},
		Changes: &engine.Changes{Since: time.Date(2026, 10, 15, 9, 0, 0, 0, time.Local), ScoreBefore: 80,
			Regressions: []engine.RuleChange{{ID: "WIN-NET-006", Title: "LLMNR deshabilitado", Severity: rule.SevHigh, Before: engine.Pass, After: engine.Fail}},
			Fixed:       []engine.RuleChange{{ID: "WIN-NET-003", Title: "Firma SMB obligatoria en el servidor", Severity: rule.SevHigh, Before: engine.Fail, After: engine.Pass}}}}
	var buf bytes.Buffer
	Console(&buf, rep, ConsoleOptions{})
	out := buf.String()
	for _, want := range []string{"CAMBIOS DESDE EL 15/10/2026 09:00", "1 empeorado, 1 corregido", "postura 80 → 70", "WIN-NET-006", "(antes superado)", "corregido", "WIN-NET-003"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en:\n%s", want, out)
		}
	}
	var html bytes.Buffer
	if err := HTML(&html, rep); err != nil || !strings.Contains(html.String(), `"regressions":[{"id":"WIN-NET-006"`) {
		t.Errorf("el informe HTML debe llevar los cambios: %v", err)
	}
}

// Los análisis de «pc» no deben mezclarse con los de «pc-a» (mismo prefijo).
func TestSurfaceHistoryPerHost(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	for _, r := range []*surface.Report{
		{Schema: surface.Schema, Host: platform.Info{Hostname: "pc"}, FinishedAt: t0, Score: 90},
		{Schema: surface.Schema, Host: platform.Info{Hostname: "pc-a"}, FinishedAt: t0.Add(time.Hour), Score: 50},
		{Schema: surface.Schema, Host: platform.Info{Hostname: "pc-a"}, FinishedAt: t0.Add(2 * time.Hour), Score: 40},
	} {
		if _, _, err := SaveSurface(dir, r, 1); err != nil {
			t.Fatal(err)
		}
	}
	prev, err := LatestSurface(dir, "pc")
	if err != nil || prev == nil || prev.Score != 90 {
		t.Fatalf("el último de «pc» es el suyo: %+v %v", prev, err)
	}
	if files := surfaceFiles(dir, "pc-a", ".json"); len(files) != 1 {
		t.Errorf("la retención de «pc-a» no toca los de «pc»: %v", files)
	}
	if files := surfaceFiles(dir, "pc", ".json"); len(files) != 1 {
		t.Errorf("guardar los de «pc-a» no borra los de «pc»: %v", files)
	}
}
