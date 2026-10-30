package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/platform"
)

func TestSafeWriterStripsEscapes(t *testing.T) {
	s := Style{on: true}
	hostile := "nc\x1b]52;c;ZWNobyBoaQ==\x07\x1b[2J\x1b[8moculto\r\b\x9b31m"
	var b bytes.Buffer
	w := SafeWriter(&b)
	_, _ = w.Write([]byte(s.Red("✗") + " proceso " + hostile + " · ñ\n"))
	got := b.String()
	if strings.ContainsAny(got, "\a\r\b") || strings.Contains(got, "\x1b]") || strings.Contains(got, "\x1b[2J") || strings.Contains(got, "\x1b[8m") || strings.Contains(got, "\u009b") {
		t.Errorf("quedan secuencias de control: %q", got)
	}
	if !strings.HasPrefix(got, "\x1b[31m✗\x1b[0m proceso nc") || !strings.HasSuffix(got, " · ñ\n") {
		t.Errorf("se pierden los colores propios o el texto: %q", got)
	}
	if c := Clean("a\tb\nc\x1b[1md"); c != "a b c[1md" {
		t.Errorf("Clean = %q", c)
	}
}

func TestCheckOutputAndWriteFile(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "notas.txt")
	if err := os.WriteFile(keep, []byte("importante"), 0o640); err != nil {
		t.Fatal(err)
	}
	rep := &engine.Report{Schema: engine.SchemaVersion}
	if err := WriteFile(keep, rep); err == nil {
		t.Error("una extensión no soportada debe rechazarse")
	}
	if b, _ := os.ReadFile(keep); string(b) != "importante" {
		t.Error("el fichero existente no debe vaciarse")
	}
	if err := CheckOutput(filepath.Join(keep, "x.html")); err == nil {
		t.Error("la carpeta de destino es un fichero")
	}
	if err := CheckOutput(dir + string(os.PathSeparator) + "sub" + string(os.PathSeparator) + "r.HTML"); err != nil {
		t.Error(err)
	}
	if err := WriteFile(filepath.Join(dir, "sub", "r.json"), rep); err != nil {
		t.Error(err)
	}
}

func TestPrunePerHost(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.Local)
	save := func(host string, day int) {
		rep := &engine.Report{Schema: engine.SchemaVersion, Host: platform.Info{Hostname: host}, FinishedAt: base.AddDate(0, 0, day)}
		if _, _, err := Save(dir, rep, 2); err != nil {
			t.Fatal(err)
		}
	}
	// «alpha» va antes alfabéticamente: antes se borraban sus informes más
	// recientes al guardar los de «zeta».
	save("alpha", 10)
	for d := 1; d <= 4; d++ {
		save("zeta", d)
	}
	if n := len(hostFiles(dir, "bastion-", "alpha", ".json")); n != 1 {
		t.Errorf("alpha: %d informes, quiero 1", n)
	}
	if n := len(hostFiles(dir, "bastion-", "zeta", ".json")); n != 2 {
		t.Errorf("zeta: %d informes, quiero 2", n)
	}
}

func TestConsoleUnscored(t *testing.T) {
	var b bytes.Buffer
	Console(&b, &engine.Report{Schema: engine.SchemaVersion, Score: engine.Score{Grade: "N/A"}}, ConsoleOptions{})
	if out := b.String(); !strings.Contains(out, "sin evaluar") || strings.Contains(out, "0/100") {
		t.Errorf("sin puntuación no debe mostrarse 0/100:\n%s", out)
	}
}
