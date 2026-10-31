package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/platform"
	"github.com/Ruby570bocadito/adarve/internal/probes"
	"github.com/Ruby570bocadito/adarve/internal/remediate"
	"github.com/Ruby570bocadito/adarve/internal/report"
	"github.com/Ruby570bocadito/adarve/internal/surface"
	"github.com/Ruby570bocadito/adarve/internal/version"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

type surfaceFixFlags struct {
	apply, yes, includeRemote, noDeadman bool
	confirmTimeout                       time.Duration
}

func newSurfaceFixCmd() *cobra.Command {
	var f surfaceFixFlags
	cmd := &cobra.Command{
		Use:   "fix [ID...]",
		Short: "Limitar a la red local las reglas del firewall que abren puertos a cualquiera",
		Long: `Corrige los hallazgos de "adarve surface" que abren puertos a cualquier
dirección: limita a la red local (LocalSubnet) las reglas del Firewall de
Windows que los abren. Sin --apply es una SIMULACIÓN: muestra el plan.

Con --apply se hace como en "harden": instantánea del estado previo, cambio,
verificación y, si algo falla, vuelta atrás; el cambio queda en "adarve
history" y se deshace con "adarve rollback". RDP, SSH, WinRM, VNC y
Sunshine solo se incluyen con --include-remote y con dead-man switch: si no
confirmas que sigues pudiendo entrar, se revierte solo.

Por ahora, solo en Windows y para las reglas del almacén local. Lo que llega
por otras reglas ya limitadas (una VPN como Tailscale, por ejemplo) sigue
llegando.`,
		Example: `  adarve surface fix                             # ver el plan (no cambia nada)
  adarve surface fix --apply                     # aplicarlo, con confirmación
  adarve surface fix SURF-APPS-OPEN --apply      # solo los programas
  adarve surface fix SURF-PORT-3389 --apply --include-remote   # RDP
  adarve rollback                                # deshacerlo`,
		RunE: func(cmd *cobra.Command, args []string) error { return runSurfaceFix(f, args) },
	}
	fl := cmd.Flags()
	fl.BoolVar(&f.apply, "apply", false, "aplicar los cambios (sin esto es una simulación)")
	fl.BoolVarP(&f.yes, "yes", "y", false, "no pedir confirmación")
	fl.BoolVar(&f.includeRemote, "include-remote", false, "incluir RDP, SSH, WinRM, VNC y Sunshine (con dead-man switch)")
	fl.BoolVar(&f.noDeadman, "no-deadman", false, "sin dead-man switch (solo máquinas desechables o laboratorios)")
	fl.DurationVar(&f.confirmTimeout, "confirm-timeout", 2*time.Minute, "plazo para confirmar el acceso remoto")
	return cmd
}

// remoteAccessPorts son los hallazgos cuyo arreglo puede cortar el acceso
// remoto con el que se administra el equipo.
var remoteAccessPorts = map[string]bool{"SURF-PORT-22": true, "SURF-PORT-3389": true, "SURF-PORT-5985": true,
	"SURF-PORT-5986": true, "SURF-PORT-5900": true, "SURF-SUNSHINE": true}

// surfaceFixRules convierte los hallazgos con reglas conocidas en reglas
// con acciones tipadas, una por regla del firewall. ids limita a esos
// hallazgos; devuelve también los pedidos que no se pueden arreglar.
//
// Una regla del firewall que abre puertos de dos hallazgos (un programa que
// abre el de SSDP y otros suyos) se limita solo con el primero, el más
// grave; si al otro no le queda ninguna, sale sin acciones y con la nota en
// el resumen.
func surfaceFixRules(rep *surface.Report, ids []string) (rules []*rule.Rule, unknown []string) {
	want := map[string]bool{}
	for _, id := range ids {
		want[strings.ToUpper(id)] = true
	}
	seen := map[string]bool{}
	owner := map[string]string{}
	for _, f := range rep.Findings {
		if len(want) > 0 && !want[f.ID] {
			continue
		}
		seen[f.ID] = true
		if len(f.FirewallRules) == 0 {
			continue
		}
		r := &rule.Rule{ID: f.ID, Title: f.Title, Severity: f.Severity, Category: "surface",
			Remediation: rule.Remediation{Summary: "Limitar a la red local las reglas que abren el puerto a cualquiera", BreakingRisk: "medium"}}
		if remoteAccessPorts[f.ID] {
			r.Remediation.Safety = "remote-access"
		}
		var shared []string
		for _, name := range f.FirewallRules {
			if o, ok := owner[name]; ok {
				if !slices.Contains(shared, o) {
					shared = append(shared, o)
				}
				continue
			}
			owner[name] = f.ID
			r.Remediation.Actions = append(r.Remediation.Actions, rule.Action{Type: "firewall.remote_address",
				Params: map[string]any{"rule": name, "remote": "LocalSubnet"}})
		}
		if len(r.Remediation.Actions) == 0 {
			r.Remediation.Summary = "sus reglas ya se limitan con " + strings.Join(shared, " y ")
		}
		rules = append(rules, r)
	}
	for _, id := range ids {
		if !seen[strings.ToUpper(id)] {
			unknown = append(unknown, strings.ToUpper(id))
		}
	}
	return rules, unknown
}

func runSurfaceFix(f surfaceFixFlags, ids []string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("adarve surface fix solo está disponible en Windows por ahora; en Linux, cada hallazgo de adarve surface explica cómo limitar el puerto (ufw, firewalld)")
	}
	if !f.noDeadman {
		if err := checkConfirmTimeout(f.confirmTimeout); err != nil {
			return err
		}
	}
	info := platform.Detect()
	if !probes.Privileged() {
		return fmt.Errorf("adarve surface fix lee las reglas del registro y las modifica: %s", report.AdminHint(info.Family))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := analyzeSurface(ctx)
	if err != nil {
		return err
	}
	rules, unknown := surfaceFixRules(rep, ids)
	if len(unknown) > 0 {
		return fmt.Errorf("no hay ningún hallazgo %s (los IDs están en adarve surface)", strings.Join(unknown, ", "))
	}
	s := stdoutStyle()
	if len(rules) == 0 {
		fmt.Printf("\n  %s Ningún hallazgo tiene reglas del firewall que limitar", s.Green(report.Sym("✓")))
		if len(rep.Findings) > 0 {
			fmt.Print(": el resto se corrige con «adarve harden» o a mano, como indica cada hallazgo")
		}
		fmt.Print(".\n\n")
		return nil
	}

	var items []*remediate.Item
	for _, r := range rules {
		if len(r.Remediation.Actions) == 0 {
			items = append(items, &remediate.Item{Rule: r, Status: remediate.ItemNothing, Reason: r.Remediation.Summary})
			continue
		}
		if r.Remediation.Safety == "remote-access" && !f.includeRemote {
			items = append(items, &remediate.Item{Rule: r, Status: remediate.ItemRemote,
				Reason: "puede cortar el acceso remoto: requiere --include-remote (con dead-man switch)"})
			continue
		}
		items = append(items, remediate.PlanRule(ctx, r))
	}
	planned, remote := printSurfaceFixPlan(s, rep, items)

	if !f.apply {
		fmt.Printf("\n  %s %s\n", s.Yellow(report.Sym("⚠")), s.Bold("Simulación: no se ha cambiado nada."))
		if planned > 0 {
			cmd := "adarve surface fix"
			if len(ids) > 0 {
				cmd += " " + strings.ToUpper(strings.Join(ids, " "))
			}
			if f.includeRemote {
				cmd += " --include-remote"
			}
			fmt.Printf("    Para aplicar: %s\n", s.Bold(cmd+" --apply"))
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
	if !f.yes && !askYesNo(fmt.Sprintf("¿Limitar %d hallazgos a la red local en %s? Se guardará una instantánea para poder deshacerlo.", planned, info.Hostname)) {
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
	signal.Ignore(syscall.SIGHUP)

	x := &remediate.Executor{
		Store:          store,
		Verify:         verifyFirewallSteps(items),
		Events:         hardenEvents(s),
		DeadmanTimeout: f.confirmTimeout,
	}
	if !f.noDeadman {
		x.ConfirmRemote = confirmRemote(s)
		x.ArmDeadman = func(id string, t time.Duration) error { return remediate.SpawnDeadman(store.Dir, id, t) }
	}
	fmt.Println()
	m, err := x.Execute(ctx, store.NewManifest(info.Hostname, "surface", version.Version, 0), items)
	if err != nil {
		return err
	}
	// Los cambios ya están aplicados y verificados regla a regla: si el
	// análisis final falla, se muestra igualmente el resumen con la
	// instantánea para poder deshacerlos, y solo se avisa.
	after, err := analyzeSurface(ctx)
	printSurfaceFixSummary(s, m, items, rep, after)
	if err != nil {
		fmt.Printf("  %s %s\n\n", s.Yellow("!"), s.Yellow("No se pudo repetir el análisis para mostrar la exposición final ("+err.Error()+"): compruébalo con adarve surface."))
	}
	if m.Status == remediate.StatusFailed {
		return &ExitError{Code: 1}
	}
	return nil
}

// verifyFirewallSteps comprueba, leyendo de nuevo cada regla, que quedó
// limitada a lo pedido.
func verifyFirewallSteps(items []*remediate.Item) func(ctx context.Context, r *rule.Rule) engine.Result {
	return func(ctx context.Context, r *rule.Rule) engine.Result {
		for _, it := range items {
			if it.Rule != r {
				continue
			}
			for _, st := range it.Steps {
				p := probes.Params(st.Action.Params)
				now, err := st.Rem.Capture(ctx, p)
				if err != nil {
					return engine.Result{Rule: r, Eval: engine.Eval{Status: engine.Fail, Message: err.Error()}}
				}
				if !remediate.Skipped(now) {
					return engine.Result{Rule: r, Eval: engine.Eval{Status: engine.Fail, Actual: fmt.Sprint(now["remote"])}}
				}
			}
		}
		return engine.Result{Rule: r, Eval: engine.Eval{Status: engine.Pass}}
	}
}

func printSurfaceFixPlan(s report.Style, rep *surface.Report, items []*remediate.Item) (planned, remote int) {
	fmt.Println()
	fmt.Printf("  %s  %s · exposición %d/100 %s\n", s.Bold("PLAN · limitar a la red local"), rep.Host.Hostname, rep.Score, rep.Grade)
	fmt.Println("  " + s.Dim(strings.Repeat("─", 72)))
	for _, it := range items {
		switch it.Status {
		case remediate.ItemPlanned:
			planned++
			if it.Remote() {
				remote++
			}
			fmt.Printf("  %s %s %s\n", s.Green("+"), s.Cyan(fmt.Sprintf("%-15s", it.Rule.ID)), report.Clean(it.Rule.Title))
			for _, st := range it.Steps {
				if remediate.Skipped(st.Before) {
					fmt.Printf("    %s %s\n", s.Dim("·"), s.Dim(report.Clean(fmt.Sprint(st.Before["reason"]))))
					continue
				}
				fmt.Printf("    %s %s\n", s.Dim("→"), report.Clean(st.Desc))
			}
			if it.Remote() {
				fmt.Printf("    %s %s\n", s.Yellow(report.Sym("⚠")), s.Yellow("acceso remoto: se aplica con dead-man switch"))
			}
		default:
			fmt.Printf("  %s %s %s\n", s.Dim("·"), s.Cyan(fmt.Sprintf("%-15s", it.Rule.ID)), report.Clean(it.Rule.Title))
			fmt.Printf("    %s\n", s.Dim(report.Clean(it.Reason)))
		}
	}
	return planned, remote
}

func printSurfaceFixSummary(s report.Style, m *remediate.Manifest, items []*remediate.Item, before, after *surface.Report) {
	verified := 0
	for _, it := range items {
		if it.Status == remediate.ItemPlanned && it.Outcome == remediate.OutcomeVerified {
			verified++
		}
	}
	fmt.Println()
	fmt.Println("  " + s.Dim(strings.Repeat("─", 72)))
	if after != nil {
		fmt.Printf("  %s  %d/100 %s  →  %s\n", s.Bold("EXPOSICIÓN"), before.Score, before.Grade, s.Bold(fmt.Sprintf("%d/100 %s", after.Score, after.Grade)))
		fmt.Printf("  %s %d hallazgos limitados a la red local · %d abiertos a cualquiera (antes %d)\n", s.Green(report.Sym("✓")), verified,
			after.Reachable-after.Limited, before.Reachable-before.Limited)
	} else {
		fmt.Printf("  %s  %d/100 %s  →  ?\n", s.Bold("EXPOSICIÓN"), before.Score, before.Grade)
		fmt.Printf("  %s %d hallazgos limitados a la red local\n", s.Green(report.Sym("✓")), verified)
	}
	if m.Status != remediate.StatusFailed && m.Status != remediate.StatusNothing {
		fmt.Printf("  %s Instantánea %s · para deshacer: %s\n", s.Cyan(report.Sym("→")), s.Bold(m.ID), s.Bold("adarve rollback "+m.ID))
	}
	fmt.Println()
}
