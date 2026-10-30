//go:build !windows

package config

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// restrictPermissions deja el directorio (y su contenido) accesible y
// modificable solo por root.
func restrictPermissions(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := os.Lchown(p, 0, 0); err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if p == dir {
			return os.Chmod(p, 0o750)
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if m := fi.Mode().Perm(); m&0o022 != 0 {
			return os.Chmod(p, m&^0o022)
		}
		return nil
	})
}

// GrantUserRead no es necesario en Linux: los informes se leen como root.
func GrantUserRead(string) error { return nil }

// CheckAdminOnly comprueba que path sea de root y que ni el grupo ni otros
// usuarios puedan escribir en él. kind no cambia nada en Unix.
func CheckAdminOnly(path string, _ Kind) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("no se pueden leer el propietario y los permisos de %s", path)
	}
	if st.Uid != 0 {
		return fmt.Errorf("%s no pertenece a root (uid %d)", path, st.Uid)
	}
	if fi.Mode()&fs.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s tiene permiso de escritura para el grupo u otros usuarios (%04o)", path, fi.Mode().Perm())
	}
	return nil
}
