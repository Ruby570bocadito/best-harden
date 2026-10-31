//go:build windows

package schedule

import (
	"fmt"
	"path/filepath"

	"github.com/Ruby570bocadito/adarve/internal/config"
)

// SafeExecutable comprueba que ningún usuario sin privilegios pueda
// sustituir el ejecutable que lanzará la tarea como SYSTEM: el fichero y su
// carpeta deben ser de Administradores, SYSTEM o TrustedInstaller sin
// permisos de escritura para nadie más, y ninguna carpeta superior puede
// permitir a otros borrarla, renombrar su contenido o cambiar sus permisos.
//
// Así se rechazan Descargas o el escritorio, pero también una carpeta de
// Program Files con permisos relajados por el instalador de otro programa.
func SafeExecutable(exe string) error {
	p, err := filepath.Abs(exe)
	if err != nil {
		return err
	}
	if err := config.CheckAdminOnly(p, config.KindFile); err != nil {
		return insecure(err)
	}
	dir := filepath.Dir(p)
	if err := config.CheckAdminOnly(dir, config.KindDir); err != nil {
		return insecure(err)
	}
	for {
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
		if err := config.CheckAdminOnly(dir, config.KindAncestor); err != nil {
			return insecure(err)
		}
	}
}

func insecure(err error) error {
	return fmt.Errorf("%w: la tarea se ejecuta como SYSTEM y quien pueda modificar el ejecutable o su carpeta obtendría esos privilegios", err)
}
