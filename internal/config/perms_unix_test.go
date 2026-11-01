//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Como root: restringe el árbol sin seguir enlaces que apuntan fuera de él.
func TestRestrictPermissionsNoFollow(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("necesita root")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "datos")
	outside := filepath.Join(base, "fuera.txt") // hace de /etc/shadow
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "sub"), 0o777))
	must(os.WriteFile(outside, []byte("secreto"), 0o600))
	must(os.Chown(outside, 1000, 1000))
	must(os.WriteFile(filepath.Join(dir, "sub", "a.txt"), nil, 0o666))
	must(os.Chmod(filepath.Join(dir, "sub", "a.txt"), 0o666))
	must(os.Chmod(filepath.Join(dir, "sub"), 0o777))
	must(os.Chmod(dir, 0o777))
	must(os.Symlink(outside, filepath.Join(dir, "sub", "enlace")))
	must(os.Lchown(filepath.Join(dir, "sub", "enlace"), 1000, 1000))
	must(os.Chown(filepath.Join(dir, "sub", "a.txt"), 1000, 1000))

	must(restrictPermissions(dir))

	mode := func(p string) os.FileMode {
		fi, err := os.Lstat(p)
		must(err)
		return fi.Mode().Perm()
	}
	owner := func(p string) int {
		fi, err := os.Lstat(p)
		must(err)
		return int(fi.Sys().(*syscall.Stat_t).Uid)
	}
	if m := mode(dir); m != 0o750 {
		t.Errorf("raíz: %o, se esperaba 750", m)
	}
	if m := mode(filepath.Join(dir, "sub")); m != 0o755 {
		t.Errorf("subdirectorio: %o, se esperaba 755", m)
	}
	if m := mode(filepath.Join(dir, "sub", "a.txt")); m != 0o644 {
		t.Errorf("fichero: %o, se esperaba 644", m)
	}
	for _, p := range []string{dir, filepath.Join(dir, "sub"), filepath.Join(dir, "sub", "a.txt"), filepath.Join(dir, "sub", "enlace")} {
		if owner(p) != 0 {
			t.Errorf("%s: dueño %d, se esperaba root", p, owner(p))
		}
	}
	// Lo de fuera, al que apuntaba el enlace, sigue igual.
	if m, o := mode(outside), owner(outside); m != 0o600 || o != 1000 {
		t.Errorf("se siguió el enlace: %s quedó con %o y dueño %d", outside, m, o)
	}

	// La raíz no puede ser un enlace.
	link := filepath.Join(base, "raiz-enlace")
	must(os.Symlink(dir, link))
	if err := restrictPermissions(link); err == nil {
		t.Error("una raíz que es un enlace debe rechazarse")
	}
}
