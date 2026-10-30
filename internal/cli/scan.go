package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/bastion/internal/config"
	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/version"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

type scanFlags struct {
	profile  string
	format   string
	outputs  []string
	save     bool
	open     bool
	minScore int
	showAll  bool
	ids      []string
	category []string
	quiet    bool
}

func newScanCmd() *cobra.Command {
	var f scanFlags
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Auditar el equipo (solo lectura)",
		Long: `Evalúa los controles del perfil y muestra la postura de seguridad.

El escaneo es de SOLO LECTURA: no modifica nada en el sistema.
Ejecuta como administrador (Windows) o root (Linux) para que todos los
controles se puedan leer.`,
		Example: `  bastion scan
  bastion scan --profile win-workstation-l2
  bastion scan --save --open
  bastion scan -o informe.html -o informe.json
  bastion scan --format json > resultado.json
  bastion scan --min-score 80          # código de salida 2 si la puntuación es menor (CI/CD)`,
		RunE: func(cmd *cobra.Command, _ []string) error { return runScan(f) },
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.profile, "profile", "p", "", "perfil a evaluar (por defecto: según la plataforma)")
	fl.StringVarP(&f.format, "format", "f", "console", "salida estándar: console | json")
	fl.StringArrayVarP(&f.outputs, "output", "o", nil, "guardar el informe en un fichero .html o .json (repetible)")
	fl.BoolVar(&f.save, "save", false, "guardar informe HTML y JSON en el directorio de informes")
	fl.BoolVar(&f.open, "open", false, "abrir el informe HTML al terminar (implica --save si no hay -o .html)")
	fl.IntVar(&f.minScore, "min-score", 0, "salir con código 2 si la puntuación es inferior")
	fl.BoolVarP(&f.showAll, "all", "a", false, "mostrar también los controles superados y no aplicables")
	fl.StringSliceVar(&f.ids, "rule", nil, "evaluar solo estas reglas (IDs)")
	fl.StringSliceVar(&f.category, "category", nil, "evaluar solo estas categorías")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "no mostrar el resumen en consola")
	return cmd
}

func runScan(f scanFlags) error {
	if f.format != "console" && f.format != "json" {
		return fmt.Errorf("--format debe ser console o json")
	}
	if f.minScore < 0 || f.minScore > 100 {
		return fmt.Errorf("--min-score debe estar entre 0 y 100")
	}
	// Los ficheros de salida se comprueban antes de escanear: un error al
	// final no debe tirar un escaneo largo ni vaciar un fichero existente.
	for _, o := range f.outputs {
		if err := report.CheckOutput(o); err != nil {
			return fmt.Errorf("-o %s: %w", o, err)
		}
	}
	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	progress := newProgress(f.format == "console" && !f.quiet)
	rep, err := scanReport(ctx, cfg, f.profile, f.ids, f.category, progress.update)
	progress.done()
	if errors.Is(err, context.Canceled) {
		// Un escaneo interrumpido no se guarda ni se escribe: sería la base
		// de la próxima comparación con la mayoría de controles en error.
		return &ExitError{Code: 130, Msg: "escaneo interrumpido: no se ha guardado nada"}
	}
	if err != nil {
		return err
	}
	attachScanChanges(cfg, rep)

	switch f.format {
	case "json":
		if err := report.JSON(os.Stdout, rep); err != nil {
			return err
		}
	default:
		if !f.quiet {
			report.Console(os.Stdout, rep, report.ConsoleOptions{ShowAll: f.showAll, Style: stdoutStyle()})
		}
	}

	// Ficheros de informe.
	msgs := os.Stdout
	if f.format == "json" {
		msgs = os.Stderr
	}
	s := report.NewStyle(msgs, gf.noColor)
	htmlOut := ""
	for _, o := range f.outputs {
		if err := report.WriteFile(o, rep); err != nil {
			return err
		}
		if strings.HasSuffix(strings.ToLower(o), ".html") {
			htmlOut = o
		}
		fmt.Fprintf(msgs, "  %s Informe guardado: %s\n", s.Cyan(report.Sym("→")), o)
	}
	if f.save || (f.open && htmlOut == "") {
		h, j, _, userDir, err := saveReport(cfg, rep)
		if err != nil {
			return err
		}
		htmlOut = h
		fmt.Fprintf(msgs, "  %s Informe HTML: %s\n", s.Cyan(report.Sym("→")), h)
		fmt.Fprintf(msgs, "  %s Informe JSON: %s\n", s.Cyan(report.Sym("→")), j)
		if userDir {
			fmt.Fprintf(msgs, "    %s\n", s.Dim("(en tu carpeta de usuario: sin privilegios no se puede escribir en "+cfg.Reports.Dir+")"))
		}
	}
	if f.open && htmlOut != "" {
		if err := report.Open(htmlOut); err != nil {
			fmt.Fprintf(msgs, "  %s No se pudo abrir el navegador (%v). Abre el fichero manualmente.\n", s.Yellow("!"), err)
		}
	}
	if f.format == "console" && !f.quiet && rep.Score.Failed > 0 {
		fmt.Fprintf(msgs, "  %s Detalle y remediación de un control: %s\n", s.Dim("·"), s.Bold("bastion rules show <ID>"))
		if htmlOut == "" {
			fmt.Fprintf(msgs, "  %s Informe visual con evidencias:       %s\n", s.Dim("·"), s.Bold("bastion scan --save --open"))
		}
		fmt.Fprintln(msgs)
	}

	if f.minScore > 0 && !rep.Score.Scored {
		return &ExitError{Code: 2, Msg: fmt.Sprintf("no se ha podido evaluar ningún control: no hay puntuación que comparar con --min-score %d (¿falta ejecutarlo con privilegios?)", f.minScore)}
	}
	if f.minScore > 0 && rep.Score.Value < f.minScore {
		return &ExitError{Code: 2, Msg: fmt.Sprintf("puntuación %d inferior al mínimo exigido (%d)", rep.Score.Value, f.minScore)}
	}
	return nil
}

// scanReport evalúa el perfil (el pedido, el de config.yaml o el del rol
// del equipo), aplica las excepciones y construye el informe.
func scanReport(ctx context.Context, cfg config.Config, profile string, ids, cats []string, progress func(int, int)) (*engine.Report, error) {
	cat, err := loadCatalog(cfg)
	if err != nil {
		return nil, err
	}
	info := platform.Detect()
	prof, err := resolveProfile(cat, info, firstNonEmpty(profile, cfg.Profile))
	if err != nil {
		return nil, err
	}
	if !rule.MatchesPlatform(prof.Platforms, info.Tags) {
		fmt.Fprintf(os.Stderr, "aviso: el perfil %s está pensado para %s y este equipo es %s\n",
			prof.ID, strings.Join(prof.Platforms, ", "), strings.Join(info.Tags, ", "))
	}
	selected := filterRules(cat.Select(info.Tags, prof.ID), ids, cats)
	if len(selected) == 0 {
		return nil, fmt.Errorf("ninguna regla aplicable con esos filtros")
	}
	started := time.Now()
	eng := engine.New()
	eng.HostTags = info.Tags
	results := evaluate(ctx, eng, selected, info, progress)
	if err := ctx.Err(); err != nil {
		// Interrumpido o caducado: los controles que quedaban saldrían como
		// error. No se devuelve un informe para que nadie lo guarde.
		return nil, fmt.Errorf("escaneo incompleto: %w", err)
	}
	finished := time.Now()
	return &engine.Report{
		Schema:     engine.SchemaVersion,
		Tool:       engine.ToolInfo{Name: "bastion", Version: version.Version, Commit: version.Commit},
		Host:       info,
		Profile:    prof,
		StartedAt:  started.UTC(),
		FinishedAt: finished.UTC(),
		DurationMs: finished.Sub(started).Milliseconds(),
		Score:      engine.ComputeScore(results),
		Results:    results,
	}, nil
}

// attachScanChanges compara el escaneo con el último guardado del mismo
// equipo y perfil: controles que han empeorado y que se han corregido.
func attachScanChanges(cfg config.Config, rep *engine.Report) {
	if rep.Profile == nil {
		return
	}
	dir, _ := reportsDir(cfg)
	metas, err := report.ListSaved(dir, rep.Host.Hostname)
	if err != nil {
		return
	}
	for i := len(metas) - 1; i >= 0; i-- {
		if metas[i].Profile != rep.Profile.ID {
			continue
		}
		if prev, err := report.LoadSaved(dir, metas[i].ID); err == nil {
			rep.Changes = engine.Diff(prev, rep)
		}
		return
	}
}

// saveReport guarda el informe HTML y JSON en el directorio de informes.
func saveReport(cfg config.Config, rep *engine.Report) (htmlPath, jsonPath, dir string, userDir bool, err error) {
	dir, userDir = reportsDir(cfg)
	if !userDir && probes.Privileged() {
		// Con privilegios se escribe en la carpeta de datos: antes, que
		// exista con sus permisos restringidos (si no, en Windows heredaría
		// los de %ProgramData%, donde cualquier usuario crea ficheros).
		if err := ensureDataDirs(); err != nil {
			return "", "", dir, userDir, err
		}
	}
	htmlPath, jsonPath, err = report.Save(dir, rep, cfg.Reports.Keep)
	if err != nil {
		return "", "", dir, userDir, fmt.Errorf("no se pudo guardar el informe en %s: %w", dir, err)
	}
	if !userDir {
		_ = config.GrantUserRead(dir) // que el navegador sin elevar pueda abrirlo
	}
	return htmlPath, jsonPath, dir, userDir, nil
}

func filterRules(rs []*rule.Rule, ids, cats []string) []*rule.Rule {
	if len(ids) == 0 && len(cats) == 0 {
		return rs
	}
	idSet, catSet := map[string]bool{}, map[string]bool{}
	for _, i := range ids {
		idSet[strings.ToUpper(strings.TrimSpace(i))] = true
	}
	for _, c := range cats {
		catSet[strings.ToLower(strings.TrimSpace(c))] = true
	}
	var out []*rule.Rule
	for _, r := range rs {
		if len(idSet) > 0 && !idSet[r.ID] {
			continue
		}
		if len(catSet) > 0 && !catSet[strings.ToLower(r.Category)] {
			continue
		}
		out = append(out, r)
	}
	return out
}

// progress muestra una barra en stderr cuando es una terminal.
type progress struct {
	on    bool
	style report.Style
	last  time.Time
}

func newProgress(enabled bool) *progress {
	st := stderrStyle()
	return &progress{on: enabled && st.Enabled(), style: st}
}

func (p *progress) update(done, total int) {
	if !p.on || (time.Since(p.last) < 50*time.Millisecond && done < total) {
		return
	}
	p.last = time.Now()
	const w = 28
	filled := done * w / total
	fmt.Fprintf(os.Stderr, "\r  %s %s%s %d/%d controles", p.style.Cyan("Evaluando"),
		p.style.Cyan(strings.Repeat("█", filled)), p.style.Dim(strings.Repeat("░", w-filled)), done, total)
}

func (p *progress) done() {
	if p.on {
		fmt.Fprint(os.Stderr, "\r\x1b[2K")
	}
}

// scoreLabel es la puntuación para mostrar: «72/100 C» o «— (sin evaluar)»
// si no se pudo evaluar ningún control (un 0/100 sería engañoso).
func scoreLabel(sc engine.Score) string {
	if !sc.Scored {
		return "— (sin evaluar)"
	}
	return fmt.Sprintf("%d/100 %s", sc.Value, sc.Grade)
}
