package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Kind indica qué se comprueba de una ruta con CheckAdminOnly.
type Kind int

const (
	// KindFile: nadie sin privilegios puede escribir, borrar ni cambiar los
	// permisos del fichero.
	KindFile Kind = iota
	// KindDir: además, nadie sin privilegios puede crear ficheros dentro.
	KindDir
	// KindAncestor: una carpeta por encima; basta con que nadie sin
	// privilegios pueda borrarla, renombrar su contenido o cambiar sus
	// permisos (crear subcarpetas, como en C:\, no permite sustituir nada).
	KindAncestor
)

// Problem es una ruta de Bastion que un usuario sin privilegios podría
// modificar.
type Problem struct {
	Path string
	Dir  bool
	Err  error
}

func (p Problem) Error() string { return p.Err.Error() }

// TrustProblems comprueba que la configuración de Bastion solo la pueden
// modificar los administradores (o root): el directorio de configuración y
// de datos, config.yaml, exceptions.yaml y rules.d. Las rutas que no existen
// no cuentan.
//
// Un config.yaml plantado por otro usuario podría apuntar las
// actualizaciones a un espejo suyo o esconder controles fallidos con
// excepciones: lo que devuelva esta función no debe usarse.
func TrustProblems() []Problem {
	var out []Problem
	check := func(path string, kind Kind) {
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			return
		}
		if err := CheckAdminOnly(path, kind); err != nil {
			out = append(out, Problem{Path: path, Dir: kind != KindFile, Err: err})
		}
	}
	check(ConfigDir(), KindDir)
	if DataDir() != ConfigDir() {
		check(DataDir(), KindDir)
	}
	check(File(), KindFile)
	check(filepath.Join(ConfigDir(), "exceptions.yaml"), KindFile)
	check(filepath.Join(ConfigDir(), "rules.d"), KindDir)
	return out
}

// Quarantine aparta un fichero no fiable (lo renombra con el sufijo
// .no-confiable-<fecha>) para que Bastion no lo vuelva a leer. Devuelve el
// nuevo nombre.
func Quarantine(path string) (string, error) {
	dst := path + ".no-confiable-" + time.Now().Format("20060102-150405")
	if err := os.Rename(path, dst); err != nil {
		return "", fmt.Errorf("no se pudo apartar %s: %w", path, err)
	}
	return dst, nil
}
