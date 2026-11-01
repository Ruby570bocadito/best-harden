package sysdir

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Cambiar las variables de entorno no cambia las rutas.
func TestIgnoresEnvironment(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("solo Windows")
	}
	evil := t.TempDir()
	t.Setenv("SystemRoot", evil)
	t.Setenv("windir", evil)
	t.Setenv("ProgramData", evil)
	for _, p := range []string{System32("cmd.exe"), WindowsTemp(), ProgramData()} {
		if strings.HasPrefix(strings.ToLower(p), strings.ToLower(evil)) {
			t.Errorf("%s sale de la variable de entorno", p)
		}
	}
	if _, err := os.Stat(System32("cmd.exe")); err != nil {
		t.Errorf("System32: %v", err)
	}
	if !strings.EqualFold(filepath.Base(filepath.Dir(System32("x.exe"))), "System32") {
		t.Errorf("System32 = %s", System32("x.exe"))
	}
}
