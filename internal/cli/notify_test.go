package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/config"
	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/notify"
	"github.com/Ruby570bocadito/adarve/internal/schedule"
	"github.com/Ruby570bocadito/adarve/internal/surface"
)

func TestScheduleEvent(t *testing.T) {
	run := schedule.Run{Time: time.Now().UTC(), ScanScore: 78, SurfaceScore: 53}

	ev := scheduleEvent("Rby", run, true, true, nil, nil)
	if ev.Level != notify.LevelInfo || ev.Title != "Adarve · Rby: análisis diario sin cambios a peor" || ev.Lines[0] != "Postura 78/100 · exposición 53/100" {
		t.Errorf("sin cambios: %+v", ev)
	}

	var exposure []surface.Change
	for i := 0; i < 10; i++ {
		exposure = append(exposure, surface.Change{Kind: surface.ChangeNew, Title: fmt.Sprintf("%d/tcp (app.exe) escucha en la red: abierto a cualquiera", 8000+i)})
	}
	regs := []engine.RuleChange{{ID: "WIN-RDP-001", Title: "NLA obligatorio para RDP"}}
	ev = scheduleEvent("Rby", run, true, true, regs, exposure)
	text := ev.Text()
	if ev.Level != notify.LevelWarning || !strings.Contains(ev.Title, "han empeorado") ||
		!strings.Contains(text, "Controles que han empeorado (1):\n· WIN-RDP-001 NLA obligatorio para RDP") ||
		!strings.Contains(text, "Cambios que aumentan la exposición (10):") || !strings.Contains(text, "· y 2 más") ||
		strings.Contains(text, "8009/tcp") || len(ev.NewExposure) != 10 {
		t.Errorf("con cambios:\n%s", text)
	}

	// Falla el escaneo: error, sin la puntuación que no se ha calculado.
	run.Errors = []string{"escaneo: catálogo roto"}
	run.ScanScore = 0
	ev = scheduleEvent("Rby", run, false, true, nil, nil)
	if ev.Level != notify.LevelError || ev.Lines[0] != "Exposición 53/100" || !strings.Contains(ev.Text(), "Errores: escaneo: catálogo roto") {
		t.Errorf("con error:\n%s", ev.Text())
	}
}

func TestNotifyText(t *testing.T) {
	if got := notifyText(config.Notify{}); got != notify.LocalName {
		t.Errorf("sin webhook: %s", got)
	}
	got := notifyText(config.Notify{Webhook: "https://ntfy.sh/tema-secreto", When: "always"})
	if strings.Contains(got, "tema-secreto") || !strings.Contains(got, "webhook ntfy (https://ntfy.sh/…)") || !strings.Contains(got, "tras cada análisis") {
		t.Errorf("con webhook: %s", got)
	}
}

func TestDeliverWebhookWhen(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer srv.Close()
	ok := notify.Event{Level: notify.LevelInfo, Title: "sin cambios"}
	bad := notify.Event{Level: notify.LevelWarning, Title: "ha empeorado"}
	n := config.Notify{Webhook: srv.URL + "/hook", Format: notify.FormatJSON}
	deliver(context.Background(), n, ok)
	if hits != 0 {
		t.Error("sin cambios a peor no se avisa al webhook por defecto")
	}
	deliver(context.Background(), n, bad)
	n.When = "always"
	deliver(context.Background(), n, ok)
	if hits != 2 {
		t.Errorf("avisos al webhook: %d, quiero 2", hits)
	}
	srv.Close()
	errs := deliver(context.Background(), n, bad)
	if len(errs) == 0 || !strings.HasPrefix(errs[len(errs)-1], "webhook: ") {
		t.Errorf("el fallo del webhook se anota: %v", errs)
	}
}
