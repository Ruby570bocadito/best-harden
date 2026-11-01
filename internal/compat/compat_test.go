package compat

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Ruby570bocadito/adarve/internal/config"
	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/exceptions"
	"github.com/Ruby570bocadito/adarve/internal/notify"
	"github.com/Ruby570bocadito/adarve/internal/remediate"
	"github.com/Ruby570bocadito/adarve/internal/surface"
)

var update = flag.Bool("update", false, "reescribe los ficheros de referencia de testdata (solo para cambios compatibles y revisados)")

// formats son los formatos estables y su forma de referencia.
var formats = []struct {
	file, schema, tag string
	value             any
	what              string
}{
	{"report.txt", engine.SchemaVersion, "json", engine.Report{}, "informe de escaneo (adarve scan --format json, informes guardados)"},
	{"surface.txt", surface.Schema, "json", surface.Report{}, "superficie de ataque (adarve surface --format json)"},
	{"notify.txt", notify.Schema, "json", notify.Event{}, "aviso por webhook en formato JSON (adarve schedule)"},
	{"exceptions.txt", exceptions.Schema, "yaml", exceptions.File{}, "excepciones (exceptions.yaml)"},
	{"change.txt", remediate.ManifestSchema, "json", remediate.Manifest{}, "manifiesto de un cambio de hardening (rollback)"},
	{"config.txt", "config.yaml", "yaml", config.Config{}, "configuración (config.yaml)"},
}

// Los nombres de los esquemas son parte del formato: cambiarlos es una
// versión nueva (v2), nunca un cambio dentro de v1.
func TestSchemaNames(t *testing.T) {
	for got, want := range map[string]string{
		engine.SchemaVersion:     "adarve.report/v1",
		surface.Schema:           "adarve.surface/v1",
		notify.Schema:            "adarve.notify/v1",
		exceptions.Schema:        "adarve.exceptions/v1",
		remediate.ManifestSchema: "adarve.change/v1",
	} {
		if got != want {
			t.Errorf("esquema %q, se esperaba %q: un cambio de versión exige la política de docs/16-formatos-y-compatibilidad.md", got, want)
		}
	}
}

// TestFrozenFormats compara la forma de cada formato estable con su
// referencia. Si falla:
//   - líneas que faltan o cambian (−): cambio incompatible. No se hace en
//     v1: hace falta una versión nueva del esquema (ver docs/16).
//   - líneas nuevas (+): cambio compatible si el campo es opcional para
//     quien lee. Se acepta con: go test ./internal/compat -update
func TestFrozenFormats(t *testing.T) {
	for _, f := range formats {
		got := Shape(reflect.TypeOf(f.value), f.tag)
		path := filepath.Join("testdata", f.file)
		header := "# " + f.schema + " · " + reflect.TypeOf(f.value).String() + " · " + f.tag + "\n# " + f.what +
			"\n# Generado por internal/compat (go test ./internal/compat -update). Ver docs/16-formatos-y-compatibilidad.md.\n"
		if *update {
			if err := os.WriteFile(path, []byte(header+strings.Join(got, "\n")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (genera la referencia con -update)", path, err)
		}
		want := map[string]bool{}
		for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
			if l != "" && !strings.HasPrefix(l, "#") {
				want[l] = true
			}
		}
		have := map[string]bool{}
		var added []string
		for _, l := range got {
			have[l] = true
			if !want[l] {
				added = append(added, "+ "+l)
			}
		}
		var removed []string
		for l := range want {
			if !have[l] {
				removed = append(removed, "− "+l)
			}
		}
		if len(removed) > 0 {
			t.Errorf("%s (%s): cambio INCOMPATIBLE, faltan o cambian campos del formato v1:\n%s\nUn campo de v1 no se quita, no se renombra ni cambia de tipo: hace falta una versión nueva del esquema (docs/16).",
				f.schema, f.file, strings.Join(removed, "\n"))
		}
		if len(added) > 0 {
			t.Errorf("%s (%s): campos nuevos:\n%s\nSi son opcionales para quien lee, es un cambio compatible: acéptalo con «go test ./internal/compat -update» y revisa el diff.",
				f.schema, f.file, strings.Join(added, "\n"))
		}
	}
}
