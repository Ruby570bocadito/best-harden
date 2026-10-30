package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/bastion/internal/config"
	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/remediate"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/version"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

type hardenFlags struct {
	profile        string
	wave           int
	ids            []string
	category       []string
	apply          bool
	yes            bool
	includeRemote  bool
	forceLocal     bool
	noDeadman      bool
	confirmTimeout time.Duration
}

func snapshotStore() *remediate.Store {
	return &remediate.Store{Dir: filepath.Join(config.DataDir(), "snapshots")}
}

func newHardenCmd() *cobra.Command {
	var f hardenFlags
	cmd := &cobra.Command{
		Use:   "harden",
		Short: "Corregir los controles fallidos (simulación por defecto)",
		Long: `Calcula y aplica los cambios necesarios para que los controles fallidos se
cumplan. Sin --apply es una SIMULACIÓN: muestra el plan y no cambia nada.

Con --apply, por cada control:
  1. guarda el estado previo en una instantánea (snapshots/<id>),
  2. aplica el cambio con acciones tipadas (nunca comandos libres),
  3. vuelve a evaluar el control y, si no se cumple o algo falla, lo revierte.

Olas por riesgo de rotura: 1 = ninguno/bajo (por defecto) · 2 = +medio · 3 = +alto.
Los cambios que pueden cortar el acceso remoto (SSH, RDP) solo se incluyen con
--include-remote y se aplican con dead-man switch: si no confirmas que sigues
pudiendo entrar, se revierten solos.`,
		Example: `  bastion harden                      # simulación de la ola 1
  bastion harden --apply              # aplicar la ola 1
  bastion harden --wave 2 --apply     # incluir riesgo medio
  bastion harden --rule WIN-NET-006 --apply
  bastion rollback                    # deshacer el último cambio`,
		RunE: func(cmd *cobra.Command, _ []string) error { return runHarden(f) },
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.profile, "profile", "p", "", "perfil (por defecto: según la plataforma)")
	fl.IntVarP(&f.wave, "wave", "w", 1, "ola máxima por riesgo de rotura: 1, 2 o 3")
	fl.StringSliceVar(&f.ids, "rule", nil, "solo estas reglas (IDs)")
	fl.StringSliceVar(&f.category, "category", nil, "solo estas categorías")
	fl.BoolVar(&f.apply, "apply", false, "aplicar los cambios (sin esto es una simulación)")
	fl.BoolVarP(&f.yes, "yes", "y", false, "no pedir confirmación")
	fl.BoolVar(&f.includeRemote, "include-remote", false, "incluir cambios que afectan al acceso remoto (SSH, RDP)")
	fl.BoolVar(&f.forceLocal, "force-local", false, "aplicar en local valores que gestiona una GPO de dominio")
	fl.BoolVar(&f.noDeadman, "no-deadman", false, "sin dead-man switch (solo máquinas desechables o laboratorios)")
	fl.DurationVar(&f.confirmTimeout, "confirm-timeout", 2*time.Minute, "plazo para confirmar el acceso remoto")
	return cmd
}

func runHarden(f hardenFlags) error {
	if f.wave < 1 || f.wave > 3 {
		return fmt.Errorf("--wave debe ser 1, 2 o 3")
	}
	if !f.noDeadman {
		if err := checkConfirmTimeout(f.confirmTimeout); err != nil {
			return err
		}
	}
	cfg := loadConfig()
	cat, err := loadCatalog(cfg)
	if err != nil {
		return err
	}
	info := platform.Detect()
	if f.apply && !info.IsAdmin {
		return fmt.Errorf("aplicar cambios requiere privilegios: ejecuta como administrador (Windows) o con sudo (Linux)")
	}
	prof, err := resolveProfile(cat, info, firstNonEmpty(f.profile, cfg.Profile))
	if err != nil {
		return err
	}
	rules := filterRules(cat.Select(info.Tags, prof.ID), f.ids, f.category)
	if len(rules) == 0 {
		return fmt.Errorf("ninguna regla aplicable con esos filtros")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	eng := engine.New()
	eng.HostTags = info.Tags
	before := evaluate(ctx, eng, rules, info, nil)
	items := remediate.BuildPlan(ctx, before, remediate.Options{
		Wave: f.wave, IncludeRemote: f.includeRemote, ForceLocal: f.forceLocal, DomainJoined: info.DomainJoined,
	})

	s := stdoutStyle()
	printPlan(s, info, prof, f, items, engine.ComputeScore(before))

	planned, remote := 0, 0
	for _, it := range items {
		if it.Status == remediate.ItemPlanned {
			planned++
			if it.Remote() {
				remote++
			}
		}
	}
	if !f.apply {
		fmt.Printf("\n  %s %s\n", s.Yellow(report.Sym("⚠")), s.Bold("Simulación: no se ha cambiado nada."))
		if planned > 0 {
			fmt.Printf("    Para aplicar: %s\n", s.Bold(hardenCmdLine(f, true)))
		}
		if !info.IsAdmin {
			if n := engine.ComputeScore(before).Skipped; n > 0 {
				fmt.Printf("    %s\n", s.Dim(fmt.Sprintf("Sin privilegios hay %d controles sin evaluar que no aparecen en el plan.", n)))
			}
			fmt.Printf("    %s\n", s.Dim("Aplicar requiere privilegios. "+report.AdminHint(info.Family)))
		}
		fmt.Println()
		return nil
	}
	if planned == 0 {
		fmt.Printf("\n  %s Nada que aplicar con estos criterios.\n\n", s.Green(report.Sym("✓")))
		return nil
	}
	if remote > 0 && f.yes && !f.noDeadman {
		return fmt.Errorf("los cambios de acceso remoto necesitan confirmación interactiva; en máquinas desechables usa --no-deadman")
	}
	if !f.yes && !askYesNo(fmt.Sprintf("¿Aplicar %d cambios en %s? Se guardará una instantánea para poder deshacerlos.", planned, info.Hostname)) {
		return &ExitError{Code: 1, Msg: cancelled}
	}

	if err := ensureDataDirs(); err != nil {
		return err
	}
	store := snapshotStore()
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	// Si se corta la sesión SSH no queremos morir a mitad de un cambio.
	signal.Ignore(syscall.SIGHUP)

	x := &remediate.Executor{
		Store: store,
		Verify: func(ctx context.Context, r *rule.Rule) engine.Result {
			return eng.Run(ctx, []*rule.Rule{r}, nil)[0]
		},
		Events:         hardenEvents(s),
		DeadmanTimeout: f.confirmTimeout,
	}
	if !f.noDeadman {
		x.ConfirmRemote = confirmRemote(s)
		x.ArmDeadman = func(id string, t time.Duration) error { return remediate.SpawnDeadman(store.Dir, id, t) }
	}
	fmt.Println()
	m, err := x.Execute(ctx, store.NewManifest(info.Hostname, prof.ID, version.Version, f.wave), items)
	if err != nil {
		return err
	}

	after := engine.ComputeScore(evaluate(ctx, eng, rules, info, nil))
	printHardenSummary(s, m, items, engine.ComputeScore(before), after)
	if m.Status == remediate.StatusFailed {
		return &ExitError{Code: 1}
	}
	return nil
}

func hardenCmdLine(f hardenFlags, apply bool) string {
	parts := []string{"bastion harden"}
	if f.wave != 1 {
		parts = append(parts, fmt.Sprintf("--wave %d", f.wave))
	}
	if f.profile != "" {
		parts = append(parts, "-p "+f.profile)
	}
	if len(f.ids) > 0 {
		parts = append(parts, "--rule "+strings.Join(f.ids, ","))
	}
	if len(f.category) > 0 {
		parts = append(parts, "--category "+strings.Join(f.category, ","))
	}
	if f.includeRemote {
		parts = append(parts, "--include-remote")
	}
	// Sin estas opciones el plan sería otro: con --force-local entran los
	// valores gestionados por GPO y con --rules-dir, las reglas propias.
	if f.forceLocal {
		parts = append(parts, "--force-local")
	}
	for _, d := range gf.rulesDir {
		parts = append(parts, "--rules-dir "+quoteArg(d))
	}
	if apply {
		parts = append(parts, "--apply")
	}
	return strings.Join(parts, " ")
}

var waveNames = map[int]string{1: "riesgo de rotura nulo o bajo", 2: "hasta riesgo medio", 3: "incluye riesgo alto"}

func printPlan(s report.Style, info platform.Info, prof *rule.Profile, f hardenFlags, items []*remediate.Item, sc engine.Score) {
	line := s.Dim(strings.Repeat("─", 72))
	fmt.Println()
	fmt.Printf("  %s  %s %s\n", s.Bold(s.Cyan(report.Sym("▲")+" BASTION")), s.Dim("·"), s.Dim("plan de hardening  "+version.Version))
	fmt.Println("  " + line)
	fmt.Printf("  %s %s %s\n", s.Dim(fmt.Sprintf("%-9s", "Equipo")), s.Bold(info.Hostname), s.Dim("· "+info.DisplayName()))
	fmt.Printf("  %s %s %s\n", s.Dim(fmt.Sprintf("%-9s", "Perfil")), prof.Name, s.Dim("("+prof.ID+")"))
	fmt.Printf("  %s %d · %s\n", s.Dim(fmt.Sprintf("%-9s", "Ola")), f.wave, waveNames[f.wave])
	fmt.Printf("  %s %s · %d controles fallidos\n", s.Dim(fmt.Sprintf("%-9s", "Postura")), scoreLabel(sc), sc.Failed)
	if sc.Exceptions > 0 {
		fmt.Printf("  %s %s\n", s.Dim(fmt.Sprintf("%-9s", "")), s.Dim(fmt.Sprintf("%d con excepción vigente: no se modifican (bastion exceptions list)", sc.Exceptions)))
	}

	groups := []struct {
		status remediate.ItemStatus
		title  string
		hint   string
	}{
		{remediate.ItemPlanned, "CAMBIOS QUE SE APLICARÁN", ""},
		{remediate.ItemWave, "REQUIEREN UNA OLA SUPERIOR", "bastion harden --wave 2 | 3"},
		{remediate.ItemRemote, "AFECTAN AL ACCESO REMOTO", "bastion harden --include-remote"},
		{remediate.ItemGPO, "GESTIONADOS POR GPO DE DOMINIO", "corrígelos en la GPO o usa --force-local"},
		{remediate.ItemManual, "REMEDIACIÓN MANUAL", "bastion rules show <ID>"},
		{remediate.ItemCaptureError, "NO SE PUDO LEER EL ESTADO", ""},
		{remediate.ItemUnsupported, "NO DISPONIBLES EN ESTA PLATAFORMA", ""},
		{remediate.ItemNothing, "SIN NADA QUE CAMBIAR", ""},
	}
	for _, g := range groups {
		var sel []*remediate.Item
		for _, it := range items {
			if it.Status == g.status {
				sel = append(sel, it)
			}
		}
		if len(sel) == 0 {
			continue
		}
		fmt.Println()
		title := s.Bold(g.title) + " " + s.Dim(fmt.Sprintf("(%d)", len(sel)))
		if g.hint != "" {
			title += "  " + s.Dim("→ "+g.hint)
		}
		fmt.Println("  " + title)
		fmt.Println("  " + line)
		for _, it := range sel {
			sev := fmt.Sprintf("%-8s", report.SeverityLabel(it.Rule.Severity))
			risk := s.Dim("riesgo " + report.RiskLabel(it.Rule.Remediation.BreakingRisk))
			if it.Rule.Remediation.RebootRequired {
				risk += s.Dim(" · reinicio")
			}
			fmt.Printf("  %s %s %s  %s\n", sev, s.Cyan(fmt.Sprintf("%-13s", it.Rule.ID)), it.Rule.Title, risk)
			switch g.status {
			case remediate.ItemPlanned:
				for _, st := range it.Steps {
					fmt.Printf("  %s %s %s\n", strings.Repeat(" ", 22), s.Dim("·"), report.Clean(st.Desc))
				}
			case remediate.ItemManual:
				fmt.Printf("  %s %s\n", strings.Repeat(" ", 22), s.Dim(it.Rule.Remediation.Summary))
			case remediate.ItemCaptureError, remediate.ItemUnsupported, remediate.ItemWave, remediate.ItemNothing:
				fmt.Printf("  %s %s\n", strings.Repeat(" ", 22), s.Dim(report.Clean(it.Reason)))
			}
		}
	}
}

func hardenEvents(s report.Style) func(remediate.Event) {
	return func(e remediate.Event) {
		switch e.Kind {
		case "verified":
			fmt.Printf("  %s %s %s\n", s.Green(report.Sym("✓")), s.Cyan(fmt.Sprintf("%-13s", e.Item.Rule.ID)), e.Item.Rule.Title)
		case "failed":
			fmt.Printf("  %s %s %s\n", s.Red(report.Sym("✗")), s.Cyan(fmt.Sprintf("%-13s", e.Item.Rule.ID)), e.Item.Rule.Title)
			fmt.Printf("  %s %s\n", strings.Repeat(" ", 15), s.Red("error: "+report.Clean(e.Item.Message)+" (revertido)"))
		case "not-effective":
			fmt.Printf("  %s %s %s\n", s.Yellow("↺"), s.Cyan(fmt.Sprintf("%-13s", e.Item.Rule.ID)), e.Item.Rule.Title)
			fmt.Printf("  %s %s\n", strings.Repeat(" ", 15), s.Yellow(report.Clean(e.Item.Message)))
		case "nothing":
			// Al aplicar, todas sus acciones se omitieron: ya no había nada
			// que cambiar (alguien lo corrigió entre el plan y la aplicación).
			fmt.Printf("  %s %s %s\n", s.Dim("·"), s.Cyan(fmt.Sprintf("%-13s", e.Item.Rule.ID)), e.Item.Rule.Title)
			fmt.Printf("  %s %s\n", strings.Repeat(" ", 15), s.Dim("sin cambios: ya estaba como se pedía"))
		case "remote-phase":
			fmt.Printf("\n  %s\n", s.Bold("Cambios de acceso remoto (con dead-man switch)"))
		case "remote-confirmed":
			fmt.Printf("  %s Acceso remoto confirmado: se mantienen los cambios.\n", s.Green(report.Sym("✓")))
		case "remote-reverted":
			fmt.Printf("  %s Acceso remoto no confirmado: cambios revertidos.\n", s.Yellow("↺"))
		}
	}
}

func confirmRemote(s report.Style) func(time.Duration) bool {
	return func(timeout time.Duration) bool {
		fmt.Printf("\n  %s %s\n", s.Yellow(report.Sym("⚠")), s.Bold("Comprueba AHORA que puedes abrir una sesión NUEVA (SSH/RDP) en este equipo."))
		fmt.Printf("    Si no confirmas en %s, los cambios de acceso remoto se revierten solos.\n", timeout.Round(time.Second))
		fmt.Printf("    Escribe %s y pulsa Intro para mantenerlos: ", s.Bold("confirmar"))
		ch := make(chan string, 1)
		go func() {
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			ch <- strings.TrimSpace(line)
		}()
		select {
		case l := <-ch:
			return strings.EqualFold(l, "confirmar")
		case <-time.After(timeout):
			fmt.Println()
			return false
		}
	}
}

func askYesNo(q string) bool {
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintln(os.Stderr, "\n  entrada no interactiva: usa --yes para confirmar")
		return false
	}
	discardPendingInput()
	fmt.Printf("\n  %s [s/N] ", q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return isYes(line)
}

// cancelled explica cómo confirmar cuando la respuesta no fue "s".
const cancelled = "cancelado: no se ha cambiado nada. Para confirmar, escribe s y pulsa Intro (o añade --yes)."

// isYes acepta s, si, sí, y o yes en cualquier caja. La consola de Windows
// puede entregar la "í" de "sí" en otra página de códigos (uno o dos bytes
// que no son ASCII): también se acepta.
func isYes(answer string) bool {
	// Solo se pasan a minúsculas las letras ASCII: strings.ToLower cambiaría
	// los bytes inválidos por U+FFFD.
	a := []byte(strings.TrimSpace(answer))
	for i, c := range a {
		if 'A' <= c && c <= 'Z' {
			a[i] = c + 'a' - 'A'
		}
	}
	return yesWord(string(a))
}

func yesWord(a string) bool {
	switch a {
	case "s", "si", "sí", "y", "yes":
		return true
	}
	if rest, ok := strings.CutPrefix(a, "s"); ok && len(rest) >= 1 && len(rest) <= 2 {
		for i := 0; i < len(rest); i++ {
			if rest[i] < 0x80 {
				return false
			}
		}
		return true
	}
	return false
}

func printHardenSummary(s report.Style, m *remediate.Manifest, items []*remediate.Item, before, after engine.Score) {
	counts := map[string]int{}
	for _, it := range items {
		if it.Status == remediate.ItemPlanned {
			counts[it.Outcome]++
		}
	}
	fmt.Println()
	fmt.Println("  " + s.Dim(strings.Repeat("─", 72)))
	fmt.Printf("  %s  %s  →  %s\n", s.Bold("POSTURA"), scoreLabel(before), s.Bold(scoreLabel(after)))
	fmt.Printf("  %s %d aplicados y verificados", s.Green(report.Sym("✓")), counts[remediate.OutcomeVerified])
	if n := counts[remediate.OutcomeFailed]; n > 0 {
		fmt.Printf("   %s %d con error (revertidos)", s.Red(report.Sym("✗")), n)
	}
	if n := counts[remediate.OutcomeNotEffective]; n > 0 {
		fmt.Printf("   %s %d sin efecto (revertidos)", s.Yellow("↺"), n)
	}
	if n := counts[remediate.OutcomeReverted]; n > 0 {
		fmt.Printf("   %s %d revertidos (acceso remoto)", s.Yellow("↺"), n)
	}
	if n := counts[remediate.OutcomeNothing]; n > 0 {
		fmt.Printf("   %s %d sin cambios (ya estaban bien)", s.Dim("·"), n)
	}
	fmt.Println()
	if m.Status == remediate.StatusNothing {
		fmt.Printf("  %s No se ha cambiado nada: no hay nada que deshacer.\n", s.Dim("·"))
	}
	if m.Status != remediate.StatusFailed && m.Status != remediate.StatusNothing {
		fmt.Printf("  %s Instantánea %s · para deshacer: %s\n", s.Cyan(report.Sym("→")), s.Bold(m.ID), s.Bold("bastion rollback "+m.ID))
	}
	if m.RebootRequired {
		fmt.Printf("  %s Reinicia el equipo para completar algunos cambios.\n", s.Yellow(report.Sym("⚠")))
	}
	fmt.Println()
}

// ---- rollback / history / deadman ------------------------------------------------

func newRollbackCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "rollback [ID]",
		Short: "Deshacer un cambio de hardening (por defecto, el último)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !platform.Detect().IsAdmin {
				return fmt.Errorf("deshacer cambios requiere privilegios de administrador/root")
			}
			store := snapshotStore()
			var m *remediate.Manifest
			var err error
			if len(args) == 1 {
				m, err = store.Load(args[0])
			} else {
				m, err = store.Latest()
			}
			if err != nil {
				return err
			}
			s := stdoutStyle()
			fmt.Printf("\n  %s %s · %s · %s\n", s.Bold("Deshacer"), s.Bold(m.ID), m.CreatedAt.Local().Format("2006-01-02 15:04"), m.Profile)
			n := 0
			for i := len(m.Entries) - 1; i >= 0; i-- {
				e := m.Entries[i]
				if e.Attempted && !e.RolledBack {
					n++
					fmt.Printf("  %s %s %s\n", s.Dim("↺"), s.Cyan(fmt.Sprintf("%-13s", e.RuleID)), e.Description)
				}
			}
			if n == 0 {
				fmt.Printf("  %s Este cambio ya está deshecho.\n\n", s.Green(report.Sym("✓")))
				return nil
			}
			if !yes && !askYesNo(fmt.Sprintf("¿Restaurar %d valores a su estado anterior?", n)) {
				return &ExitError{Code: 1, Msg: cancelled}
			}
			unlock, err := store.Lock()
			if err != nil {
				return err
			}
			defer unlock()
			// Se relee con el bloqueo tomado: mientras se pedía confirmación,
			// el dead-man switch u otro rollback pudo cambiar el manifiesto.
			if m, err = store.Load(m.ID); err != nil {
				return err
			}
			if err := remediate.Rollback(context.Background(), m, nil); err != nil {
				return fmt.Errorf("rollback incompleto: %w", err)
			}
			fmt.Printf("  %s Cambio %s deshecho.\n\n", s.Green(report.Sym("✓")), m.ID)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "no pedir confirmación")
	return cmd
}

func newHistoryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "history",
		Short: "Listar los cambios de hardening aplicados",
		RunE: func(cmd *cobra.Command, _ []string) error {
			all, err := snapshotStore().List()
			if err != nil {
				return err
			}
			if len(all) == 0 {
				fmt.Println("No hay cambios registrados.")
				return nil
			}
			s := stdoutStyle()
			names := map[string]string{
				remediate.StatusApplied: "aplicado", remediate.StatusPartial: "parcial", remediate.StatusFailed: "fallido",
				remediate.StatusRolledBack: "deshecho", remediate.StatusInProgress: "interrumpido", remediate.StatusNothing: "sin cambios",
			}
			var tb report.Table
			tb.Row(report.Styled("CAMBIO", s.Bold), report.Styled("FECHA", s.Bold), report.Styled("PERFIL", s.Bold), report.Styled("OLA", s.Bold), report.Styled("ESTADO", s.Bold), report.Styled("CONTROLES", s.Bold))
			for _, m := range all {
				ok := 0
				for _, r := range m.Rules {
					if r.Outcome == remediate.OutcomeVerified {
						ok++
					}
				}
				wave := strconv.Itoa(m.Wave)
				if m.Wave == 0 {
					wave = "—" // bastion surface fix no va por olas
				}
				tb.Row(m.ID, m.CreatedAt.Local().Format("2006-01-02 15:04"), m.Profile, wave, names[m.Status], fmt.Sprintf("%d de %d", ok, len(m.Rules)))
			}
			tb.Write(os.Stdout)
			return nil
		},
	}
}

func newDeadmanCmd() *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:    "deadman ID",
		Short:  "Uso interno: revierte el acceso remoto si no se confirma a tiempo",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			signal.Ignore(syscall.SIGHUP)
			return remediate.RunDeadman(context.Background(), snapshotStore(), args[0], timeout)
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 2*time.Minute, "plazo de confirmación")
	return cmd
}
