package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/adarve/internal/config"
	"github.com/Ruby570bocadito/adarve/internal/platform"
	"github.com/Ruby570bocadito/adarve/internal/probes"
	"github.com/Ruby570bocadito/adarve/internal/report"
	"github.com/Ruby570bocadito/adarve/internal/selfupdate"
	"github.com/Ruby570bocadito/adarve/internal/version"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// ---- info ------------------------------------------------------------------

func newInfoCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Mostrar la plataforma detectada, el perfil por defecto y las rutas",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := loadConfig()
			info := platform.Detect()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			prof, _ := resolveProfile(cat, info, cfg.Profile)
			repDir, _ := reportsDir(cfg)
			if asJSON {
				out := map[string]any{"version": version.Version, "host": info, "config": config.File(), "reports": repDir}
				if prof != nil {
					out["default_profile"] = prof.ID
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			s := stdoutStyle()
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			row := func(k, v string) { fmt.Fprintf(w, "  %s\t%s\n", s.Dim(k), v) }
			fmt.Fprintln(os.Stdout)
			row("Versión", version.String())
			row("Equipo", info.Hostname)
			row("Sistema", info.DisplayName())
			if info.Build != "" {
				row("Build", info.Build)
			}
			if info.Kernel != "" {
				row("Kernel", info.Kernel)
			}
			row("Arquitectura", info.Arch)
			row("Rol", info.Role)
			if info.DomainJoined {
				row("Dominio", info.Domain)
			}
			row("Etiquetas", strings.Join(info.Tags, ", "))
			row("Administrador", map[bool]string{true: s.Green("sí"), false: s.Yellow("no (algunos controles no se podrán leer)")}[info.IsAdmin])
			if prof != nil {
				row("Perfil por defecto", prof.ID+" · "+prof.Name)
			}
			row("Reglas aplicables", fmt.Sprint(len(cat.Select(info.Tags, profID(prof)))))
			row("Probes disponibles", strings.Join(probes.Available(), ", "))
			row("Configuración", config.File())
			row("Informes", repDir)
			w.Flush()
			fmt.Fprintln(os.Stdout)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "salida JSON")
	return cmd
}

func profID(p *rule.Profile) string {
	if p == nil {
		return ""
	}
	return p.ID
}

// ---- rules -----------------------------------------------------------------

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "rules", Short: "Consultar y validar reglas"}

	var all bool
	var profile string
	list := &cobra.Command{
		Use:   "list",
		Short: "Listar las reglas aplicables a este equipo (o todas con --all)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := loadConfig()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			var rs []*rule.Rule
			switch {
			case all:
				rs = append(rs, cat.Rules...)
				rule.SortRules(rs)
			default:
				info := platform.Detect()
				p, err := resolveProfile(cat, info, firstNonEmpty(profile, cfg.Profile))
				if err != nil {
					return err
				}
				rs = cat.Select(info.Tags, p.ID)
			}
			s := stdoutStyle()
			var tb report.Table
			tb.Row(report.Styled("ID", s.Bold), report.Styled("SEVERIDAD", s.Bold), report.Styled("CATEGORÍA", s.Bold), report.Styled("TÍTULO", s.Bold))
			for _, r := range rs {
				tb.Row(r.ID, report.SeverityLabel(r.Severity), r.Category, r.Title)
			}
			tb.Write(os.Stdout)
			fmt.Printf("\n%d reglas\n", len(rs))
			return nil
		},
	}
	list.Flags().BoolVar(&all, "all", false, "todas las plataformas y perfiles")
	list.Flags().StringVarP(&profile, "profile", "p", "", "perfil")

	show := &cobra.Command{
		Use:   "show <ID>",
		Short: "Mostrar el detalle y la remediación de una regla",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadConfig()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			r := cat.Rule(args[0])
			if r == nil {
				return fmt.Errorf("no existe la regla %s", args[0])
			}
			printRule(r)
			if e, expired := loadExceptions().Find(r.ID, platform.Detect().Hostname, time.Now()); e != nil {
				s := stdoutStyle()
				state := s.Blue(fmt.Sprintf("vigente hasta el %s", e.Expires))
				if expired {
					state = s.Yellow("caducada el " + e.Expires)
				}
				fmt.Printf("  %s %s · %s · %s\n\n", s.Bold("EXCEPCIÓN"), state, e.Owner, e.Reason)
			}
			return nil
		},
	}

	lint := &cobra.Command{
		Use:   "lint [directorio...]",
		Short: "Validar el paquete oficial y, opcionalmente, reglas propias",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.Default()
			cfg.Rules.ExtraDirs = args
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			fmt.Printf(report.Sym("✓")+" %d reglas y %d perfiles válidos\n", len(cat.Rules), len(cat.Profiles))
			return nil
		},
	}
	doc := &cobra.Command{
		Use:   "doc",
		Short: "Generar el catálogo de controles en Markdown (docs/06-catalogo-de-controles.md)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := loadConfig()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			writeCatalogMarkdown(os.Stdout, cat)
			return nil
		},
	}
	cmd.AddCommand(list, show, lint, doc)
	return cmd
}

// writeCatalogMarkdown genera el catálogo de controles implementados.
func writeCatalogMarkdown(w io.Writer, cat *rule.Catalog) {
	groups := []struct {
		title string
		match func(*rule.Rule) bool
	}{
		{"Linux", func(r *rule.Rule) bool { return strings.HasPrefix(r.Platforms[0], "linux") }},
		{"Windows y Windows Server", func(r *rule.Rule) bool { return strings.HasPrefix(r.Platforms[0], "windows") }},
	}
	profiles := make([]*rule.Profile, 0, len(cat.Profiles))
	for _, p := range cat.Profiles {
		profiles = append(profiles, p)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })

	fmt.Fprintln(w, "<!-- Generado con \"adarve rules doc\". No editar a mano: edita las reglas en rules/. -->")
	auto := 0
	for _, r := range cat.Rules {
		if len(r.Remediation.Actions) > 0 {
			auto++
		}
	}
	fmt.Fprintf(w, "\n**%d controles** en el paquete oficial, **%d con corrección automática** (`adarve harden`). ⚡ = afecta al acceso remoto (requiere `--include-remote`).\n\n", len(cat.Rules), auto)
	fmt.Fprintln(w, "### Perfiles")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Perfil | Nombre | Hereda de | Por defecto en |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, p := range profiles {
		fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n", p.ID, p.Name, strings.Join(p.Extends, ", "), strings.Join(p.DefaultFor, ", "))
	}
	for _, g := range groups {
		var rs []*rule.Rule
		for _, r := range cat.Rules {
			if g.match(r) {
				rs = append(rs, r)
			}
		}
		sort.SliceStable(rs, func(i, j int) bool {
			if rs[i].Category != rs[j].Category {
				return rs[i].Category < rs[j].Category
			}
			return rs[i].ID < rs[j].ID
		})
		fmt.Fprintf(w, "\n### %s (%d)\n", g.title, len(rs))
		cur := ""
		for _, r := range rs {
			if r.Category != cur {
				cur = r.Category
				fmt.Fprintf(w, "\n#### %s\n\n", cur)
				fmt.Fprintln(w, "| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |")
				fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
			}
			auto := ""
			if len(r.Remediation.Actions) > 0 {
				auto = "✓"
				if r.Remediation.Safety == "remote-access" {
					auto = "✓ ⚡"
				}
			}
			fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s | %s | %s |\n", r.ID, strings.ReplaceAll(r.Title, "|", "\\|"),
				strings.ToLower(report.SeverityLabel(r.Severity)), strings.Join(r.Profiles, ", "),
				strings.Join(r.References.MitreTechniques, ", "), report.RiskLabel(r.Remediation.BreakingRisk), auto)
		}
	}
}

func printRule(r *rule.Rule) {
	s := stdoutStyle()
	sec := func(t string) { fmt.Printf("\n  %s\n", s.Bold(strings.ToUpper(t))) }
	para := func(t string) {
		for _, l := range strings.Split(strings.TrimSpace(t), "\n") {
			fmt.Printf("  %s\n", l)
		}
	}
	fmt.Printf("\n  %s  %s\n", s.Cyan(s.Bold(r.ID)), s.Bold(r.Title))
	fmt.Printf("  %s · %s · %s\n", report.SeverityLabel(r.Severity), r.Category, s.Dim(strings.Join(r.Platforms, ", ")))
	sec("Descripción")
	para(r.Description)
	if r.Rationale != "" {
		sec("Por qué importa")
		para(r.Rationale)
	}
	sec("Remediación")
	para(r.Remediation.Summary)
	if r.Remediation.GPO != "" {
		fmt.Printf("  %s %s\n", s.Dim("GPO:"), r.Remediation.GPO)
	}
	if r.Remediation.Commands != "" {
		fmt.Println()
		for _, l := range strings.Split(strings.TrimRight(r.Remediation.Commands, "\n"), "\n") {
			fmt.Printf("    %s\n", s.Green(l))
		}
	}
	if n := len(r.Remediation.Actions); n > 0 {
		cmdline := "adarve harden --rule " + r.ID + " --apply"
		if w := rule.RiskWave(r.Remediation.BreakingRisk); w > 1 {
			cmdline += fmt.Sprintf(" --wave %d", w)
		}
		if r.Remediation.Safety == "remote-access" {
			cmdline += " --include-remote"
		}
		fmt.Printf("\n  %s %d acción(es) automática(s) · %s\n", s.Green("Corrección automática:"), n, s.Bold(cmdline))
	}
	fmt.Printf("\n  %s %s", s.Dim("Riesgo de rotura:"), report.RiskLabel(r.Remediation.BreakingRisk))
	if r.Remediation.RebootRequired {
		fmt.Print(" · requiere reinicio")
	}
	fmt.Println()
	if r.Impact != "" {
		sec("Impacto")
		para(r.Impact)
	}
	refs := r.References
	var parts []string
	add := func(label string, xs []string) {
		if len(xs) > 0 {
			parts = append(parts, label+" "+strings.Join(xs, ", "))
		}
	}
	add("ATT&CK", refs.MitreTechniques)
	add("Mitigaciones", refs.MitreMitigations)
	add("NIST 800-53", refs.NIST)
	add("CIS", refs.CIS)
	add("STIG", refs.STIG)
	add("ENS", refs.ENS)
	if len(parts) > 0 {
		sec("Referencias")
		for _, p := range parts {
			fmt.Printf("  %s\n", p)
		}
	}
	fmt.Printf("\n  %s %s · perfiles: %s\n\n", s.Dim("Fuente:"), r.Source, strings.Join(r.Profiles, ", "))
}

// ---- profiles ----------------------------------------------------------------

func newProfilesCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "Listar los perfiles de hardening disponibles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := loadConfig()
			cat, err := loadCatalog(cfg)
			if err != nil {
				return err
			}
			info := platform.Detect()
			tags := info.Tags
			if all {
				tags = nil
			}
			def := cat.DefaultProfile(info.Tags)
			s := stdoutStyle()
			var tb report.Table
			tb.Row(report.Styled("PERFIL", s.Bold), report.Styled("NOMBRE", s.Bold), report.Styled("HEREDA DE", s.Bold), report.Styled("REGLAS", s.Bold))
			for _, p := range cat.ProfilesFor(tags) {
				id := report.Styled(p.ID, nil)
				if def != nil && p.ID == def.ID {
					id = report.Styled(p.ID+" (por defecto)", s.Green)
				}
				n := len(cat.Select(representativeTags(p.Platforms), p.ID))
				if !all {
					n = len(cat.Select(info.Tags, p.ID))
				}
				tb.Row(id, p.Name, strings.Join(p.Extends, ", "), strconv.Itoa(n))
			}
			tb.Write(os.Stdout)
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "incluir perfiles de otras plataformas")
	return cmd
}

// ---- update ------------------------------------------------------------------

// planUpdate decide si instalar target sobre current y lo explica.
// explicit indica que la versión se pidió con --version (puede ser una
// vuelta atrás); force reinstala aunque no haga falta.
func planUpdate(current, target string, explicit, force bool) (install bool, msg string) {
	if !selfupdate.IsRelease(current) {
		if force {
			return true, fmt.Sprintf("Compilación de desarrollo (%s): se instala %s.", current, target)
		}
		return false, fmt.Sprintf("Esta es una compilación de desarrollo (%s): no se compara con las versiones publicadas (%s). Para sustituirla: adarve update --force", current, target)
	}
	cmp, _ := selfupdate.Compare(target, current)
	switch {
	case cmp > 0:
		return true, fmt.Sprintf("Hay una versión nueva: %s.", target)
	case cmp == 0 && force:
		return true, fmt.Sprintf("Se reinstala %s.", target)
	case cmp == 0 && explicit:
		return false, "Ya tienes esa versión."
	case cmp == 0:
		return false, "Adarve está actualizado."
	case explicit:
		return true, fmt.Sprintf("%s es anterior a la instalada: se vuelve atrás.", target)
	case force:
		return true, fmt.Sprintf("Se instala %s, anterior a la instalada.", target)
	}
	return false, fmt.Sprintf("Adarve está actualizado (la versión instalada es posterior a la última publicada, %s).", target)
}

func newUpdateCmd() *cobra.Command {
	var check, force, pause bool
	var wanted, repo, releasesURL string
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Actualizar Adarve (y su paquete de reglas) a la última versión",
		Long: `Descarga la última release, verifica su suma SHA-256 y sustituye el binario.
Las reglas oficiales van incrustadas en el binario, así que también se actualizan.

Origen: https://github.com/<repo>/releases, o un espejo interno (siempre
HTTPS) con --releases-url, update.releases_url en config.yaml o la variable
ADARVE_RELEASES_URL. Con privilegios, las variables ADARVE_RELEASES_URL y
ADARVE_REPO se ignoran salvo con --trust-env: cualquier programa del
usuario podría fijarlas para que el administrador instale su binario.`,
		Example: `  adarve update
  adarve update --check
  adarve update --version v0.3.2          # una versión concreta, también anterior
  adarve update --releases-url https://mirror.interno/adarve/releases`,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			if pause {
				// Ventana de administrador abierta por la elevación: que no
				// se cierre antes de poder leer el resultado.
				defer func() {
					if err != nil {
						fmt.Fprintln(os.Stderr, "error:", err)
						code := 1
						var ee *ExitError
						if errors.As(err, &ee) {
							code = ee.Code
						}
						err = &ExitError{Code: code}
					}
					fmt.Print("\n  Pulsa Intro para cerrar esta ventana…")
					_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
				}()
			}
			cfg := loadConfig()
			src := selfupdate.Source{
				Repo:    firstNonEmpty(repo, config.Env("REPO"), cfg.Update.Repo, version.Repo),
				BaseURL: firstNonEmpty(releasesURL, config.Env("RELEASES_URL"), cfg.Update.ReleasesURL),
			}
			if err := src.Validate(); err != nil {
				return err
			}
			s := stdoutStyle()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			current := version.Version
			var target string
			if wanted != "" {
				// Versión concreta: no depende de "latest" (que GitHub cachea
				// unos minutos tras publicar) y permite volver atrás.
				if !selfupdate.ValidTag(wanted) {
					return fmt.Errorf("--version %q no es una versión válida (ejemplo: v0.3.2)", wanted)
				}
				target = "v" + strings.TrimPrefix(wanted, "v")
				fmt.Printf("  Versión instalada: %s · versión pedida: %s\n", current, target)
			} else {
				fmt.Printf("  Comprobando %s …\n", src.Base())
				target, err = src.Latest(ctx)
				if err != nil {
					return fmt.Errorf("no se pudo consultar la última versión: %w", err)
				}
				fmt.Printf("  Versión instalada: %s · última publicada: %s\n", current, target)
			}
			install, msg := planUpdate(current, target, wanted != "", force)
			if !install {
				fmt.Printf("  %s %s\n", s.Green(report.Sym("✓")), msg)
				return nil
			}
			if wanted != "" {
				// Antes de pedir la elevación: que la versión exista.
				if err := src.Published(ctx, target); selfupdate.IsNotFound(err) {
					return fmt.Errorf("la versión %s no está publicada en %s. Si acabas de crear la etiqueta, "+
						"la release tarda unos minutos en aparecer: vuelve a intentarlo luego", target, src.Base())
				} else if err != nil {
					return fmt.Errorf("no se pudo comprobar la versión %s: %w", target, err)
				}
			}
			if check {
				line := "adarve update"
				if wanted != "" {
					line += " --version " + target
				}
				if force {
					line += " --force"
				}
				fmt.Printf("  %s %s Para instalarla: %s\n", s.Yellow(report.Sym("↑")), msg, line)
				return nil
			}
			fmt.Printf("  %s\n", msg)
			// En Windows, Adarve vive en Program Files: sin elevar no se puede
			// sustituir. En vez de fallar al final, se repite la actualización
			// en una ventana de administrador (como hace el instalador) y se
			// espera a que termine. El proceso elevado no hereda las variables
			// de esta consola: el origen se le pasa explícitamente.
			if dir, werr := selfupdate.InstallDirWritable(); werr != nil && !probes.Privileged() {
				if !canElevate() {
					return fmt.Errorf("no se puede escribir en %s: repite con sudo (sudo adarve update)", dir)
				}
				args := []string{"update", "--pause", "--version", target, "--repo", src.Repo}
				if src.BaseURL != "" {
					args = append(args, "--releases-url", src.BaseURL)
				}
				if force || !selfupdate.IsRelease(current) {
					args = append(args, "--force")
				}
				if gf.noColor {
					args = append(args, "--no-color")
				}
				fmt.Printf("  %s %s solo lo puede modificar un administrador.\n", s.Yellow("!"), dir)
				fmt.Println("    Se abre una ventana de administrador para terminar la actualización (acepta el aviso de Windows).")
				code, err := relaunchElevated(args)
				if err != nil {
					return err
				}
				if code != 0 {
					return &ExitError{Code: code, Msg: fmt.Sprintf("la actualización en la ventana de administrador terminó con el código %d", code)}
				}
				fmt.Printf("  %s Actualizado a %s\n", s.Green(report.Sym("✓")), target)
				return nil
			}
			fmt.Printf("  Descargando %s …\n", selfupdate.AssetName(runtimeGOOS(), runtimeGOARCH()))
			bin, tmp, err := src.Download(ctx, target)
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmp)
			fmt.Printf("  %s Suma SHA-256 verificada\n", s.Green(report.Sym("✓")))
			if err := selfupdate.Apply(bin); err != nil {
				return err
			}
			fmt.Printf("  %s Actualizado a %s\n", s.Green(report.Sym("✓")), target)
			return nil
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "solo comprobar si hay una versión nueva")
	cmd.Flags().BoolVar(&force, "force", false, "reinstalar aunque no haya versión nueva (o sustituir una compilación de desarrollo)")
	cmd.Flags().StringVar(&wanted, "version", "", "instalar una versión concreta (p. ej. v0.3.2), también anterior")
	cmd.Flags().StringVar(&repo, "repo", "", "repositorio de GitHub (owner/nombre)")
	cmd.Flags().StringVar(&releasesURL, "releases-url", "", "espejo interno de releases (https://…)")
	cmd.Flags().BoolVar(&pause, "pause", false, "esperar a Intro al terminar (ventana abierta por la elevación)")
	_ = cmd.Flags().MarkHidden("pause")
	return cmd
}

// ---- init ----------------------------------------------------------------------

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Preparar directorios y configuración (lo ejecuta el instalador)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			selfupdate.CleanupOld()
			if probes.Privileged() {
				// Si las carpetas ya existían con permisos inseguros, aparta
				// los ficheros que otro usuario pudo dejar antes de
				// restringirlas (si no, se volverían de confianza).
				if err := secureDataDirs(); err != nil {
					return err
				}
			}
			res, err := config.Init()
			if err != nil {
				return fmt.Errorf("init: %w (¿se ejecuta como administrador/root?)", err)
			}
			s := stdoutStyle()
			sort.Strings(res.Created)
			for _, c := range res.Created {
				fmt.Printf("  %s creado %s\n", s.Green("+"), c)
			}
			fmt.Printf("  %s Adarve preparado · configuración: %s\n", s.Green(report.Sym("✓")), res.Config)
			return nil
		},
	}
}

// ---- version --------------------------------------------------------------------

func newVersionCmd() *cobra.Command {
	var short bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Mostrar la versión",
		Run: func(cmd *cobra.Command, _ []string) {
			if short {
				fmt.Println(version.Version)
				return
			}
			fmt.Println(version.String())
		},
	}
	cmd.Flags().BoolVar(&short, "short", false, "solo el número de versión")
	return cmd
}

// representativeTags expande las plataformas de un perfil a las etiquetas
// que tendría un equipo típico de esa plataforma (para contar reglas).
func representativeTags(platforms []string) []string {
	expand := map[string][]string{
		"windows-dc":     {"windows-dc", "windows-server", "windows"},
		"windows-server": {"windows-member", "windows-server", "windows"},
		"windows-member": {"windows-member", "windows-server", "windows"},
		"windows-client": {"windows-client", "windows"},
		"linux":          {"linux-ubuntu", "linux-debian", "linux"},
	}
	var out []string
	for _, p := range platforms {
		if e, ok := expand[p]; ok {
			out = append(out, e...)
		} else {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
