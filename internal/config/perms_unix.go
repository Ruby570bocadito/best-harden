//go:build !windows

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// restrictPermissions deja el directorio (y su contenido) accesible y
// modificable solo por root.
//
// El directorio puede haberlo creado otro usuario antes que Adarve. Por eso
// no se recorre por rutas (os.Chmod sigue enlaces: si ese usuario cambia un
// fichero por un enlace a /etc/shadow entre la comprobación y el cambio, root
// le aplicaría los permisos), sino por descriptores: cada entrada se abre con
// openat y O_NOFOLLOW relativa a su directorio ya abierto, y se cambia con
// fchown/fchmod. Los enlaces simbólicos solo cambian de propietario, sin
// seguirlos.
func restrictPermissions(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	return restrictFD(fd, dir, true)
}

// restrictFD restringe lo abierto en fd (y lo cierra): root como dueño, 0750
// en el directorio raíz y, en el resto, sin escritura para grupo ni otros.
func restrictFD(fd int, name string, top bool) error {
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	perm := uint32(st.Mode) & 0o777
	want := perm &^ 0o022
	if top {
		want = 0o750
	}
	if want != uint32(st.Mode)&0o7777 && (top || perm&0o022 != 0) {
		if err := unix.Fchmod(fd, want); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil
	}
	names, err := f.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	for _, n := range names {
		child := filepath.Join(name, n)
		// O_NONBLOCK: abrir una FIFO no se queda esperando.
		cfd, err := unix.Openat(fd, n, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENXIO) {
			// Enlace simbólico (o socket): solo el propietario, sin seguirlo.
			if err := unix.Fchownat(fd, n, 0, 0, unix.AT_SYMLINK_NOFOLLOW); err != nil && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("%s: %w", child, err)
			}
			continue
		}
		if errors.Is(err, unix.ENOENT) {
			continue // desapareció mientras tanto
		}
		if err != nil {
			return fmt.Errorf("%s: %w", child, err)
		}
		if err := restrictFD(cfd, child, false); err != nil {
			return err
		}
	}
	return nil
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
