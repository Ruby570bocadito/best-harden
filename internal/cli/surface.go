package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/bastion/internal/config"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/surface"
	"github.com/Ruby570bocadito/bastion/internal/version"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

type surfaceFlags struct {
	format, failOn       string
	outputs              []string
	all, save, failOnNew bool
}

func newSurfaceCmd() *cobra.Command {
	var f surfaceFlags
	cmd := &cobra.Command{
		Use:   "surface",
		Short: "Analizar la superficie de ataque: qué servicios escuchan en la red (solo lectura)",
		Long: `Responde a "¿qué puede tocar un atacante desde la red?":

  - servicios a la escucha con su dirección, alcance (red o solo local),
    proceso y, en Windows, servicios que lo usan;
  - servicios de riesgo expuestos (Telnet, SMB, RDP, Redis, Docker API…)
    con el motivo y cómo cerrarlos;
  - recursos compartidos (SMB, NFS, Samba) abiertos a todos;
  - miembros con privilegios de administración.

Calcula una puntuación de exposición de 0 a 100 y, si hay un análisis
guardado (--save), muestra qué ha cambiado desde entonces: servicios
nuevos, puertos que el firewall deja más o menos abiertos y hallazgos
nuevos o resueltos.

Es de SOLO LECTURA; para corregir lo que abren las reglas del firewall,
"bastion surface fix". Ejecuta como administrador o root para ver el
proceso de cada puerto.`,
		Example: `  bastion surface
  bastion surface --all                 # incluir lo que solo escucha en localhost
  bastion surface --format json > superficie.json
  bastion surface -o superficie.html    # informe autocontenido para compartir o imprimir
  bastion surface --save                # guardarlo para comparar con el próximo
  bastion surface --save --fail-on-new  # código 3 si la exposición ha crecido (tareas programadas)
  bastion surface --fail-on high        # código 2 si hay hallazgos altos o críticos (CI/CD)
  bastion surface fix                   # plan para limitar a la red local lo abierto a cualquiera`,
		RunE: func(cmd *cobra.Command, _ []string) error { return runSurface(f) },
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.format, "format", "f", "console", "salida estándar: console | json")
	fl.StringArrayVarP(&f.outputs, "output", "o", nil, "guardar el análisis en ficheros .html (informe para compartir) o .json; se puede repetir")
	fl.StringVar(&f.failOn, "fail-on", "", "salir con código 2 si hay hallazgos de esta severidad o mayor: critical | high | medium | low")
	fl.BoolVarP(&f.all, "all", "a", false, "mostrar también los servicios que solo escuchan en el propio equipo")
	fl.BoolVar(&f.save, "save", false, "guardar el análisis (HTML y JSON) para comparar con el siguiente")
	fl.BoolVar(&f.failOnNew, "fail-on-new", false, "salir con código 3 si la exposición ha crecido desde el último análisis guardado")
	cmd.AddCommand(newSurfaceFixCmd())
	return cmd
}

// analyzeSurface recoge el inventario y lo analiza.
func analyzeSurface(ctx context.Context) (*surface.Report, error) {
	inv, err := surface.Collect(ctx)
	if err != nil {
		return nil, err
	}
	return surface.Analyze(inv, platform.Detect(), version.Version, time.Now()), nil
}

// attachSurfaceChanges compara el análisis con el último guardado del
// equipo. Devuelve el directorio de informes y si es el del usuario.
func attachSurfaceChanges(cfg config.Config, rep *surface.Report) (dir string, userDir bool) {
	dir, userDir = reportsDir(cfg)
	prev, err := report.LatestSurface(dir, rep.Host.Hostname)
	switch {
	case err != nil && !errors.Is(err, fs.ErrPermission):
		fmt.Fprintln(os.Stderr, "aviso: no se pudo leer el último análisis guardado:", err)
	case prev != nil:
		rep.Changes = surface.Diff(prev, rep)
	}
	return dir, userDir
}

func runSurface(f surfaceFlags) error {
	format, outputs, failOn, all := f.format, f.outputs, f.failOn, f.all
	if format != "console" && format != "json" {
		return fmt.Errorf("--format debe ser console o json")
	}
	var threshold rule.Severity
	if failOn != "" {
		threshold = rule.Severity(strings.ToLower(failOn))
		if !threshold.Valid() || threshold == rule.SevInfo {
			return fmt.Errorf("--fail-on debe ser critical, high, medium o low")
		}
	}
	for _, o := range outputs {
		if err := report.CheckOutput(o); err != nil {
			return fmt.Errorf("-o %s: %w", o, err)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := analyzeSurface(ctx)
	if ctx.Err() != nil {
		return &ExitError{Code: 130, Msg: "análisis interrumpido: no se ha guardado nada"}
	}
	if err != nil {
		return err
	}
	cfg := loadConfig()
	dir, userDir := attachSurfaceChanges(cfg, rep)
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		report.SurfaceConsole(os.Stdout, rep, all, stdoutStyle())
	}
	for _, output := range outputs {
		var buf bytes.Buffer
		switch strings.ToLower(filepath.Ext(output)) {
		case ".json":
			b, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				return err
			}
			buf.Write(append(b, '\n'))
		case ".html", ".htm":
			if err := report.SurfaceHTML(&buf, rep); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(filepath.Dir(output), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(output, buf.Bytes(), 0o640); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "  %s Análisis guardado: %s\n", report.Sym("→"), output)
	}
	if f.save {
		if !userDir {
			if err := ensureDataDirs(); err != nil {
				return err
			}
		}
		h, _, err := report.SaveSurface(dir, rep, cfg.Reports.Keep)
		if err != nil {
			return fmt.Errorf("no se pudo guardar el análisis en %s: %w", dir, err)
		}
		if !userDir {
			_ = config.GrantUserRead(dir)
		}
		fmt.Fprintf(os.Stderr, "  %s Análisis guardado para comparar con el próximo: %s\n", report.Sym("→"), h)
	}
	if f.failOnNew && rep.Changes != nil {
		for _, c := range rep.Changes.Items {
			if c.Bad() {
				return &ExitError{Code: 3, Msg: "la exposición ha crecido desde el último análisis guardado"}
			}
		}
	}
	if threshold != "" {
		for _, f := range rep.Findings {
			if f.Severity.Rank() <= threshold.Rank() {
				return &ExitError{Code: 2, Msg: fmt.Sprintf("hay hallazgos de severidad %s o mayor", strings.ToLower(report.SeverityLabel(threshold)))}
			}
		}
	}
	return nil
}
