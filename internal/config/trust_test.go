package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckAdminOnly(t *testing.T) {
	// Un fichero recién creado en la carpeta temporal es del usuario que
	// ejecuta las pruebas: solo es «de administrador» si las pruebas corren
	// como root.
	f := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(f, []byte("profile: auto\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(f, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckAdminOnly(f, KindFile); err == nil {
		t.Error("un fichero con escritura para todos (o de un usuario) no es fiable")
	}

	sys := "/bin/sh"
	if runtime.GOOS == "windows" {
		sys = filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll")
	}
	if err := CheckAdminOnly(sys, KindFile); err != nil {
		t.Errorf("%s solo lo modifican los administradores: %v", sys, err)
	}
	if err := CheckAdminOnly(filepath.Dir(sys), KindAncestor); err != nil {
		t.Errorf("%s: %v", filepath.Dir(sys), err)
	}
}

func TestTrustProblems(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("como root, la carpeta temporal ya es de root")
	}
	home := t.TempDir()
	t.Setenv("ADARVE_HOME", home)
	if err := os.WriteFile(File(), []byte("profile: auto\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	probs := TrustProblems()
	var dir, file bool
	for _, p := range probs {
		dir = dir || (p.Path == home && p.Dir)
		file = file || (p.Path == File() && !p.Dir)
	}
	if !dir || !file {
		t.Errorf("un ADARVE_HOME del usuario no es fiable: %v", probs)
	}
	dst, err := Quarantine(File())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(File()); !os.IsNotExist(err) {
		t.Error("el fichero apartado no debe seguir en su sitio")
	}
	if _, err := os.Stat(dst); err != nil {
		t.Error(err)
	}
}
