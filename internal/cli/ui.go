package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/bastion/internal/config"
	"github.com/Ruby570bocadito/bastion/internal/engine"
	"github.com/Ruby570bocadito/bastion/internal/exceptions"
	"github.com/Ruby570bocadito/bastion/internal/platform"
	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/internal/remediate"
	"github.com/Ruby570bocadito/bastion/internal/report"
	"github.com/Ruby570bocadito/bastion/internal/schedule"
	"github.com/Ruby570bocadito/bastion/internal/surface"
	"github.com/Ruby570bocadito/bastion/internal/ui"
	"github.com/Ruby570bocadito/bastion/internal/version"
)

func newUICmd() *cobra.Command {
	var port int
	var noOpen bool
	var profile string
	cmd := &cobra.Command{
		Use:   "ui",
		Short: "Abrir la consola local en el navegador (postura, tendencia, plan e historial)",
		Long: `Abre una consola en el navegador con la postura del equipo, la evolución de
la puntuación, el plan de hardening por olas, el historial de escaneos y de
cambios y las excepciones.

La consola solo escucha en 127.0.0.1 y exige el token aleatorio que aparece
en la dirección: nadie más (ni otra web ni otro usuario del equipo) puede
usarla. Solo lee y escanea; los cambios se aplican desde la terminal con
"bastion harden".

En un servidor sin escritorio, fija el puerto y usa un túnel SSH:
  bastion ui --port 8790 --no-open
  ssh -L 8790:127.0.0.1:8790 usuario@servidor   # y abre la dirección en tu equipo`,
		Example: `  bastion ui
  bastion ui --port 8790 --no-open`,
		RunE: func(cmd *cobra.Command, _ []string) error { return runUI(port, noOpen, profile) },
	}
	cmd.Flags().IntVar(&port, "port", 0, "puerto en 127.0.0.1 (por defecto, uno libre)")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "no abrir el navegador")
	cmd.Flags().StringVarP(&profile, "profile", "p", "", "perfil a evaluar (por defecto: según la plataforma)")
	return cmd
}

func runUI(port int, noOpen bool, profile string) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("--port debe estar entre 1 y 65535 (o 0: uno libre al azar)")
	}
	cfg := loadConfig()
	b := &uiBackend{cfg: cfg, profile: profile, info: platform.Detect()}
	if _, err := loadCatalog(cfg); err != nil {
		return err
	}
	srv, err := ui.New(b)
	if err != nil {
		return err
	}
	l, err := ui.Listen(port)
	if err != nil {
		return fmt.Errorf("no se pudo abrir el puerto %d en 127.0.0.1: %w", port, err)
	}
	base := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(l.Addr().(*net.TCPAddr).Port))
	// La dirección con el token solo se muestra en la terminal. El
	// navegador se abre con un fichero local privado que redirige con un
	// código de un solo uso: el token no pasa por la línea de órdenes del
	// navegador, que cualquier usuario del equipo puede leer en /proc.
	url := base + "/?t=" + srv.Token()

	s := stdoutStyle()
	fmt.Println()
	fmt.Printf("  %s  %s %s\n", s.Bold(s.Cyan(report.Sym("▲")+" BASTION")), s.Dim("·"), s.Dim("consola local  "+version.Version))
	fmt.Printf("\n  %s %s\n", s.Dim("Dirección:"), s.Bold(url))
	fmt.Printf("  %s\n", s.Dim("Solo accesible desde este equipo y con el token de la dirección. Ctrl+C para cerrar."))
	if !b.info.IsAdmin {
		fmt.Printf("  %s %s\n", s.Yellow(report.Sym("⚠")), s.Yellow("Sin privilegios algunos controles quedarán sin evaluar. "+report.AdminHint(b.info.Family)))
	}
	fmt.Println()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if !noOpen {
		launcher, cleanup, err := srv.WriteLauncher(base)
		if err == nil {
			defer cleanup()
			err = report.Open(launcher)
		}
		if err != nil {
			fmt.Printf("  %s No se pudo abrir el navegador (%v): copia la dirección.\n\n", s.Yellow("!"), err)
		}
	}
	return srv.Serve(ctx, l)
}

// uiBackend implementa ui.Backend con los mismos componentes que la CLI.
type uiBackend struct {
	cfg     config.Config
	profile string
	info    platform.Info
}

func (b *uiBackend) State() ui.State {
	st := ui.State{Version: version.Version, Hostname: b.info.Hostname, System: b.info.DisplayName(), Family: b.info.Family,
		Role: b.info.Role, IsAdmin: b.info.IsAdmin}
	st.ReportsDir, _ = reportsDir(b.cfg)
	if cat, err := loadCatalog(b.cfg); err == nil {
		if p, err := resolveProfile(cat, b.info, firstNonEmpty(b.profile, b.cfg.Profile)); err == nil {
			st.Profile, st.ProfileID = p.Name, p.ID
		}
	}
	return st
}

func (b *uiBackend) Scan(ctx context.Context) (*engine.Report, string, error) {
	rep, err := scanReport(ctx, b.cfg, b.profile, nil, nil, nil)
	if err != nil {
		return nil, "", err
	}
	attachScanChanges(b.cfg, rep)
	_, jsonPath, _, _, err := saveReport(b.cfg, rep)
	if err != nil {
		return nil, "", err
	}
	return rep, strings.TrimSuffix(filepath.Base(jsonPath), ".json"), nil
}

func (b *uiBackend) Reports() ([]report.Meta, error) {
	dir, _ := reportsDir(b.cfg)
	return report.ListSaved(dir, b.info.Hostname)
}

func (b *uiBackend) Report(id string) (*engine.Report, error) {
	dir, _ := reportsDir(b.cfg)
	return report.LoadSaved(dir, id)
}

func (b *uiBackend) Plan(ctx context.Context, wave int) ([]ui.PlanItem, error) {
	cat, err := loadCatalog(b.cfg)
	if err != nil {
		return nil, err
	}
	prof, err := resolveProfile(cat, b.info, firstNonEmpty(b.profile, b.cfg.Profile))
	if err != nil {
		return nil, err
	}
	eng := engine.New()
	eng.HostTags = b.info.Tags
	results := evaluate(ctx, eng, cat.Select(b.info.Tags, prof.ID), b.info, nil)
	items := remediate.BuildPlan(ctx, results, remediate.Options{Wave: wave, DomainJoined: b.info.DomainJoined})
	out := make([]ui.PlanItem, 0, len(items))
	for _, it := range items {
		p := ui.PlanItem{RuleID: it.Rule.ID, Title: it.Rule.Title, Severity: string(it.Rule.Severity), Category: it.Rule.Category,
			Status: string(it.Status), Reason: it.Reason, Summary: it.Rule.Remediation.Summary,
			Risk: it.Rule.Remediation.BreakingRisk, Reboot: it.Rule.Remediation.RebootRequired}
		for _, st := range it.Steps {
			p.Steps = append(p.Steps, st.Desc)
		}
		out = append(out, p)
	}
	return out, nil
}

func (b *uiBackend) Changes() ([]ui.Change, error) {
	ms, err := snapshotStore().List()
	if err != nil {
		return nil, err
	}
	out := make([]ui.Change, 0, len(ms))
	for _, m := range ms {
		c := ui.Change{ID: m.ID, CreatedAt: m.CreatedAt, Wave: m.Wave, Status: m.Status, Profile: m.Profile, Reboot: m.RebootRequired}
		for _, r := range m.Rules {
			switch r.Outcome {
			case remediate.OutcomeVerified:
				c.Verified++
			case remediate.OutcomeFailed, remediate.OutcomeNotEffective:
				c.Failed++
			case remediate.OutcomeNothing:
				c.Nothing++
			}
		}
		for _, e := range m.Entries {
			if e.RolledBack {
				c.RolledBack++
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func (b *uiBackend) Schedule(ctx context.Context) (*ui.ScheduleInfo, error) {
	info := &ui.ScheduleInfo{}
	if runs, err := schedule.ReadRuns(schedule.LogPath(config.DataDir())); err == nil {
		if len(runs) > 10 {
			runs = runs[len(runs)-10:]
		}
		info.Runs = runs
	}
	sched, err := schedule.New()
	if err != nil {
		info.Unsupported = true
		return info, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	st, err := sched.Get(ctx)
	if err != nil {
		st.Detail = "no se pudo consultar la tarea: " + err.Error()
	}
	info.Status = st
	if st.Mechanism != "" && probes.Privileged() {
		info.Notify = notifyText(loadConfig().Notify)
	}
	return info, nil
}

func (b *uiBackend) Surface(ctx context.Context) (*surface.Report, error) {
	rep, err := analyzeSurface(ctx)
	if err == nil {
		attachSurfaceChanges(loadConfig(), rep)
	}
	return rep, err
}

func (b *uiBackend) Exceptions() ([]ui.Exception, error) {
	if !configTrusted() {
		return nil, fmt.Errorf("exceptions.yaml no es fiable: otro usuario podría haberlo modificado (bastion init restablece los permisos)")
	}
	f, err := exceptions.Load(exceptionsPath())
	if err != nil && len(f.Exceptions) == 0 {
		return nil, err
	}
	now := time.Now()
	out := make([]ui.Exception, 0, len(f.Exceptions))
	for _, e := range f.Exceptions {
		out = append(out, ui.Exception{Rule: e.Rule, Reason: e.Reason, Owner: e.Owner, Hosts: e.Hosts,
			Created: e.Created, Expires: e.Expires, Expired: e.Expired(now), DaysLeft: e.DaysLeft(now)})
	}
	return out, nil
}
