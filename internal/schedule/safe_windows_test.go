//go:build windows

package schedule

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafeExecutableWindows(t *testing.T) {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	if err := SafeExecutable(sys); err != nil {
		t.Errorf("%s solo lo modifican los administradores: %v", sys, err)
	}
	exe := filepath.Join(t.TempDir(), "bastion.exe") // carpeta del usuario
	if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SafeExecutable(exe); err == nil {
		t.Error("un ejecutable en la carpeta temporal del usuario no es seguro para una tarea de SYSTEM")
	}
}
