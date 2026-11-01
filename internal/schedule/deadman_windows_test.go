//go:build windows

package schedule

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Ruby570bocadito/adarve/internal/probes"
)

// Con el Programador de tareas de verdad: la tarea del dead-man switch es de
// SYSTEM, arranca en cada inicio del equipo y desaparece al desarmarla.
func TestDeadmanTaskReal(t *testing.T) {
	if os.Getenv("CI") != "true" || !probes.Privileged() {
		t.Skip("registra una tarea real del Programador de tareas: solo en el CI, como administrador")
	}
	ctx := context.Background()
	id := "chg-20000101-000000"
	// whoami.exe con argumentos que no entiende termina enseguida, con
	// error y sin tocar nada.
	exe := probes.System32("whoami.exe")
	d := taskScheduler{}
	t.Cleanup(func() { _ = d.DisarmDeadman(ctx, id, true) })
	if err := d.ArmDeadman(ctx, exe, id); err != nil {
		t.Fatal(err)
	}
	out, err := runPS(ctx, psDeadman+`$t = Get-ScheduledTask -TaskPath $tp -TaskName $n; `+
		`@{trigger=[string]$t.Triggers[0].CimClass.CimClassName; user=[string]$t.Principal.UserId; level=[string]$t.Principal.RunLevel; `+
		`exe=[string]$t.Actions[0].Execute; args=[string]$t.Actions[0].Arguments; `+
		`battery=[bool]$t.Settings.DisallowStartIfOnBatteries; stopBattery=[bool]$t.Settings.StopIfGoingOnBatteries} | ConvertTo-Json -Compress`,
		"ADARVE_ID="+id)
	if err != nil {
		t.Fatal(err)
	}
	var task struct {
		Trigger, User, Level, Exe, Args string
		Battery, StopBattery            bool
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &task); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if task.Trigger != "MSFT_TaskBootTrigger" {
		t.Errorf("disparador %q: debe arrancar en cada inicio del equipo", task.Trigger)
	}
	if task.User != "SYSTEM" && task.User != "S-1-5-18" || task.Level != "Highest" {
		t.Errorf("usuario %q, nivel %q: debe ser SYSTEM con privilegios", task.User, task.Level)
	}
	if !strings.EqualFold(task.Exe, exe) || task.Args != "deadman "+id {
		t.Errorf("acción: %q %q", task.Exe, task.Args)
	}
	if task.Battery || task.StopBattery {
		t.Error("en un portátil debe arrancar y seguir con batería")
	}
	if err := d.DisarmDeadman(ctx, id, true); err != nil {
		t.Fatal(err)
	}
	out, err = runPS(ctx, psDeadman+`[bool](Get-ScheduledTask -TaskPath $tp -TaskName $n -ErrorAction SilentlyContinue)`, "ADARVE_ID="+id)
	if err != nil || strings.TrimSpace(out) != "False" {
		t.Errorf("la tarea debe desaparecer al desarmarla: %q %v", out, err)
	}
}
