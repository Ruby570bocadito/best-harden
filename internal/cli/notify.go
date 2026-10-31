package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Ruby570bocadito/adarve/internal/config"
	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/notify"
	"github.com/Ruby570bocadito/adarve/internal/report"
	"github.com/Ruby570bocadito/adarve/internal/schedule"
	"github.com/Ruby570bocadito/adarve/internal/surface"
	"github.com/Ruby570bocadito/adarve/internal/version"
)

func newScheduleNotifyCmd() *cobra.Command {
	var set, format, when string
	var clear bool
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Configurar y probar los avisos del análisis programado",
		Long: `Cada análisis programado queda anotado en el Visor de eventos de Windows
(Registros de Windows › Aplicación, origen Adarve) o en syslog en Linux
(journalctl -t adarve): como aviso si la postura o la exposición han
empeorado y como error si ha fallado.

Además, puede avisar a un webhook: ntfy (notificaciones en el móvil, sin
cuenta), Slack, Discord, Microsoft Teams o cualquier servicio que acepte
JSON. Por defecto solo cuando algo empeora o falla (--when always: también
cuando no hay cambios a peor). El aviso lleva el resumen (equipo,
puntuaciones y títulos de los cambios), nunca evidencias.

Sin opciones, envía un aviso de prueba por todos los canales. Con --set,
primero prueba el webhook y solo lo guarda si el aviso llega.

La dirección suele llevar un secreto (el tema de ntfy, el token de Slack):
con --set - se lee de la entrada estándar y no queda en el historial de la
shell ni en la lista de procesos, que otros usuarios pueden ver.`,
		Example: `  adarve schedule notify                                  # probar los avisos
  adarve schedule notify --set https://ntfy.sh/adarve-casa-7f3k9
  adarve schedule notify --set https://hooks.slack.com/services/… --when always
  sudo adarve schedule notify --set - < webhook.txt         # sin la dirección en la línea de órdenes
  adarve schedule notify --clear`,
		RunE: func(cmd *cobra.Command, _ []string) error { return scheduleNotify(set, format, when, clear) },
	}
	cmd.Flags().StringVar(&set, "set", "", "dirección del webhook (https://…), o - para leerla de la entrada estándar; para ntfy, https://ntfy.sh/<tema difícil de adivinar>")
	cmd.Flags().StringVar(&format, "format", "", "formato: "+strings.Join(notify.Formats, ", ")+" (por defecto se deduce de la dirección)")
	cmd.Flags().StringVar(&when, "when", "", "cuándo avisar al webhook: changes (si algo empeora o falla) o always")
	cmd.Flags().BoolVar(&clear, "clear", false, "quitar el webhook (el Visor de eventos o syslog siguen registrando cada ejecución)")
	return cmd
}

func scheduleNotify(set, format, when string, clear bool) error {
	if set == "-" {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("--set -: no se pudo leer la dirección de la entrada estándar: %w", err)
		}
		if set = strings.TrimSpace(line); set == "" {
			return fmt.Errorf("--set -: la entrada estándar está vacía")
		}
	}
	if format != "" && !slices.Contains(notify.Formats, format) {
		return fmt.Errorf("formato %q desconocido: usa %s", format, strings.Join(notify.Formats, ", "))
	}
	if when != "" && when != "changes" && when != "always" {
		return fmt.Errorf("--when admite changes o always")
	}
	if (format != "" || when != "") && set == "" {
		return fmt.Errorf("--format y --when acompañan a --set")
	}
	if set != "" && clear {
		return fmt.Errorf("usa --set o --clear, no los dos")
	}
	if err := requireAdmin("configurar los avisos"); err != nil {
		return err
	}
	if err := ensureDataDirs(); err != nil {
		return err
	}
	s := stdoutStyle()
	cfg := loadConfig()
	fmt.Println()
	if clear {
		if err := config.SetNotify(config.Notify{}); err != nil {
			return err
		}
		fmt.Printf("  %s Webhook quitado. Cada ejecución sigue quedando en %s.\n\n", s.Green(report.Sym("✓")), notify.LocalName)
		return nil
	}
	n := cfg.Notify
	if set != "" {
		if _, err := notify.ValidateURL(set); err != nil {
			return err
		}
		n = config.Notify{Webhook: strings.TrimSpace(set), Format: format, When: when}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ev := testEvent()
	failed := false
	if err := notify.Local(ev); err != nil {
		fmt.Printf("  %s %s: %v\n", s.Red("×"), notify.LocalName, err)
		failed = true
	} else {
		fmt.Printf("  %s %s: aviso de prueba registrado\n", s.Green(report.Sym("✓")), notify.LocalName)
	}
	if n.Webhook == "" {
		fmt.Printf("  %s Sin webhook. Para recibir los avisos en el móvil (app ntfy, sin cuenta): %s\n",
			s.Dim("·"), s.Bold("adarve schedule notify --set https://ntfy.sh/<tema-difícil-de-adivinar>"))
	} else if err := notify.Webhook(ctx, n.Webhook, n.Format, "adarve/"+version.Version, ev); err != nil {
		fmt.Printf("  %s Webhook %s: %v\n", s.Red("×"), webhookName(n), err)
		if set != "" {
			fmt.Printf("    %s\n", s.Dim("No se ha guardado. Revisa la dirección y vuelve a intentarlo."))
		}
		failed = true
	} else {
		fmt.Printf("  %s Webhook %s: aviso de prueba enviado\n", s.Green(report.Sym("✓")), webhookName(n))
		if set != "" {
			if err := config.SetNotify(n); err != nil {
				return fmt.Errorf("el aviso ha llegado, pero no se pudo guardar en %s: %w", config.File(), err)
			}
			fmt.Printf("  %s Guardado en %s: %s\n", s.Green(report.Sym("✓")), config.File(), whenText(n.When))
		}
	}
	fmt.Println()
	if failed {
		return &ExitError{Code: 1}
	}
	return nil
}

// testEvent es el aviso de prueba.
func testEvent() notify.Event {
	host, _ := os.Hostname()
	ev := notify.Event{Host: host, Time: time.Now().UTC(), Level: notify.LevelInfo, Test: true,
		Title: fmt.Sprintf("Adarve · %s: aviso de prueba", host),
		Lines: []string{"Si lees esto, los avisos del análisis programado llegan bien."}}
	if runs, err := schedule.ReadRuns(schedule.LogPath(config.DataDir())); err == nil && len(runs) > 0 {
		r := runs[len(runs)-1]
		ev.ScanScore, ev.SurfaceScore = r.ScanScore, r.SurfaceScore
		ev.Lines = append(ev.Lines, fmt.Sprintf("Último análisis (%s): postura %s · exposición %d/100",
			r.Time.Local().Format("2006-01-02 15:04"), runScanText(r), r.SurfaceScore))
	}
	return ev
}

func webhookName(n config.Notify) string {
	f := n.Format
	if f == "" {
		if u, err := notify.ValidateURL(n.Webhook); err == nil {
			f = notify.FormatFor(u)
		}
	}
	return fmt.Sprintf("%s (%s)", f, notify.Redact(n.Webhook))
}

func whenText(when string) string {
	if when == "always" {
		return "avisa tras cada análisis"
	}
	return "avisa si la postura o la exposición empeoran o el análisis falla"
}

// notifyText describe los avisos configurados.
func notifyText(n config.Notify) string {
	if n.Webhook == "" {
		return notify.LocalName
	}
	return notify.LocalName + " · webhook " + webhookName(n) + ", " + whenText(n.When)
}

// scheduleEvent resume una ejecución del análisis programado para avisar.
func scheduleEvent(host string, run schedule.Run, scanOK, surfaceOK bool, regressions []engine.RuleChange, exposure []surface.Change) notify.Event {
	ev := notify.Event{Host: host, Time: run.Time, Level: notify.LevelInfo, ScanScore: run.ScanScore, SurfaceScore: run.SurfaceScore, Errors: run.Errors}
	var scores []string
	if scanOK {
		scores = append(scores, "postura "+runScanText(run))
	}
	if surfaceOK {
		scores = append(scores, fmt.Sprintf("exposición %d/100", run.SurfaceScore))
	}
	if len(scores) > 0 {
		line := strings.Join(scores, " · ")
		ev.Lines = append(ev.Lines, strings.ToUpper(line[:1])+line[1:])
	}
	list := func(head string, items []string, max int) {
		if len(items) == 0 {
			return
		}
		ev.Lines = append(ev.Lines, fmt.Sprintf("%s (%d):", head, len(items)))
		for i, it := range items {
			if i == max {
				ev.Lines = append(ev.Lines, fmt.Sprintf("· y %d más", len(items)-max))
				break
			}
			ev.Lines = append(ev.Lines, "· "+it)
		}
	}
	for _, r := range regressions {
		ev.Regressions = append(ev.Regressions, r.ID+" "+r.Title)
	}
	for _, c := range exposure {
		ev.NewExposure = append(ev.NewExposure, c.Title)
	}
	list("Controles que han empeorado", ev.Regressions, 5)
	list("Cambios que aumentan la exposición", ev.NewExposure, 8)
	if len(run.Errors) > 0 {
		ev.Lines = append(ev.Lines, "Errores: "+strings.Join(run.Errors, "; "))
	}
	ev.Lines = append(ev.Lines, "Detalle en el equipo: adarve surface · adarve scan · adarve ui")
	switch {
	case len(run.Errors) > 0:
		ev.Level = notify.LevelError
		ev.Title = fmt.Sprintf("Adarve · %s: el análisis programado ha fallado", host)
	case len(regressions) > 0 || len(exposure) > 0:
		ev.Level = notify.LevelWarning
		ev.Title = fmt.Sprintf("Adarve · %s: la postura o la exposición han empeorado", host)
	default:
		ev.Title = fmt.Sprintf("Adarve · %s: análisis diario sin cambios a peor", host)
	}
	return ev
}

// deliver avisa de una ejecución: siempre en el registro del sistema y, si
// hay webhook, cuando algo empeora o falla (o siempre, con when: always).
// Devuelve los fallos, para anotarlos en schedule.log.
func deliver(ctx context.Context, n config.Notify, ev notify.Event) []string {
	var errs []string
	if err := notify.Local(ev); err != nil {
		errs = append(errs, "registro del sistema: "+err.Error())
	}
	if n.Webhook != "" && (ev.Level != notify.LevelInfo || n.When == "always") {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := notify.Webhook(ctx, n.Webhook, n.Format, "adarve/"+version.Version, ev); err != nil {
			errs = append(errs, "webhook: "+err.Error())
		}
	}
	return errs
}
