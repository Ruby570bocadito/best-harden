package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetNotify(t *testing.T) {
	t.Setenv("ADARVE_HOME", t.TempDir())
	// Sin config.yaml: se crea el de por defecto con la sección.
	if err := SetNotify(Notify{Webhook: "https://ntfy.sh/adarve-rby", When: "always"}); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil || c.Notify.Webhook != "https://ntfy.sh/adarve-rby" || c.Notify.When != "always" || c.Notify.Format != "" || c.Reports.Keep != 30 {
		t.Fatalf("tras crear: %+v %v", c, err)
	}
	b, _ := os.ReadFile(File())
	if !strings.Contains(string(b), "# Perfil por defecto") || !strings.Contains(string(b), "# releases_url:") {
		t.Errorf("se conservan los comentarios:\n%s", b)
	}

	// Cambiarla no la duplica y respeta el resto.
	if err := os.WriteFile(File(), []byte(strings.Replace(string(b), "keep: 30", "keep: 12", 1)), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SetNotify(Notify{Webhook: "https://hooks.slack.com/services/T/B/X", Format: "slack"}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(File())
	c, _ = Load()
	if strings.Count(string(b), "\nnotify:") != 1 || c.Notify.Format != "slack" || c.Notify.When != "" || c.Reports.Keep != 12 {
		t.Errorf("tras cambiar: %+v\n%s", c.Notify, b)
	}

	// Sin webhook se quita la sección.
	if err := SetNotify(Notify{}); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(File())
	if c, _ := Load(); c.Notify.Webhook != "" || strings.Contains(string(b), "\nnotify:") {
		t.Errorf("tras quitar:\n%s", b)
	}

	// Un config.yaml roto no se sobrescribe.
	if err := os.WriteFile(File(), []byte("profile: [roto"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SetNotify(Notify{Webhook: "https://ntfy.sh/x"}); err == nil {
		t.Error("con un config.yaml roto debería fallar")
	}
}

func TestMigrated(t *testing.T) {
	base := t.TempDir()
	dir, legacy := filepath.Join(base, "Adarve"), filepath.Join(base, "Bastion")

	// Sin ninguna de las dos: la nueva.
	if got := migrated(dir, legacy); got != dir {
		t.Fatalf("sin carpetas: %s", got)
	}

	// Solo la de Bastion: se traslada con su contenido.
	if err := os.MkdirAll(filepath.Join(legacy, "reports"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "exceptions.yaml"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if got := migrated(dir, legacy); got != dir {
		t.Fatalf("tras migrar: %s", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "exceptions.yaml")); err != nil {
		t.Errorf("el contenido no se trasladó: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("la carpeta de Bastion sigue ahí: %v", err)
	}

	// Las dos: manda la nueva y la antigua no se toca.
	if err := os.Mkdir(legacy, 0o750); err != nil {
		t.Fatal(err)
	}
	if got := migrated(dir, legacy); got != dir {
		t.Errorf("con las dos: %s", got)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Errorf("con las dos, la de Bastion no debe tocarse: %v", err)
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("ADARVE_REPO", "")
	t.Setenv("BASTION_REPO", "viejo/bastion")
	if got := Env("REPO"); got != "viejo/bastion" {
		t.Errorf("con la variable antigua: %q", got)
	}
	t.Setenv("ADARVE_REPO", "nuevo/adarve")
	if got := Env("REPO"); got != "nuevo/adarve" {
		t.Errorf("la nueva manda: %q", got)
	}
}
