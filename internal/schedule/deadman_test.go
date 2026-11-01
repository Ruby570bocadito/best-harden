package schedule

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

const testChange = "chg-20261015-193000"

func TestDeadmanSystemd(t *testing.T) {
	u, calls := fakeUnix(t, true)
	ctx := context.Background()
	if err := u.ArmDeadman(ctx, "/opt/mis herramientas/adarve", testChange); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(u.path(deadmanTemplate))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ExecStart="/opt/mis herramientas/adarve" deadman %i`,
		"Type=simple",
		// En cada inicio del equipo, hasta que se desactive.
		"WantedBy=multi-user.target",
		"Description=Adarve: dead-man switch del acceso remoto (%i)",
	} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("falta %q en la plantilla:\n%s", want, unit)
		}
	}
	if got := strings.Join(*calls, "\n"); got != "systemctl daemon-reload\nsystemctl enable --now adarve-deadman@"+testChange+".service" {
		t.Errorf("órdenes al armar:\n%s", got)
	}

	*calls = nil
	if err := u.DisarmDeadman(ctx, testChange, true); err != nil {
		t.Fatal(err)
	}
	if err := u.DisarmDeadman(ctx, testChange, false); err != nil {
		t.Fatal(err)
	}
	want := "systemctl disable --now adarve-deadman@" + testChange + ".service\n" +
		"systemctl disable adarve-deadman@" + testChange + ".service"
	if got := strings.Join(*calls, "\n"); got != want {
		t.Errorf("órdenes al desarmar (con y sin parar la ejecución):\n%s", got)
	}
}

// El ID forma parte del nombre de la unidad y de la orden: solo se aceptan
// ID de cambio.
func TestDeadmanRejectsOtherIDs(t *testing.T) {
	u, calls := fakeUnix(t, true)
	ctx := context.Background()
	for _, id := range []string{"", "chg-1", "../" + testChange, testChange + ".service", testChange + " --now", "chg-20261015-193000\nx"} {
		if err := u.ArmDeadman(ctx, "/usr/local/bin/adarve", id); err == nil {
			t.Errorf("ArmDeadman(%q) debe rechazarse", id)
		}
		if err := u.DisarmDeadman(ctx, id, true); err == nil {
			t.Errorf("DisarmDeadman(%q) debe rechazarse", id)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("no debe llegar nada a systemctl: %v", *calls)
	}
}

// Sin systemd no hay tarea del sistema: armDeadman (internal/cli) recurre al
// proceso independiente. Desarmar no tiene nada que quitar.
func TestDeadmanWithoutSystemd(t *testing.T) {
	u, calls := fakeUnix(t, false)
	ctx := context.Background()
	if err := u.ArmDeadman(ctx, "/usr/local/bin/adarve", testChange); !errors.Is(err, ErrUnsupported) {
		t.Errorf("sin systemd: %v, quiero ErrUnsupported", err)
	}
	if err := u.DisarmDeadman(ctx, testChange, true); err != nil {
		t.Error(err)
	}
	if len(*calls) != 0 {
		t.Errorf("no debe llegar nada a systemctl: %v", *calls)
	}
}
