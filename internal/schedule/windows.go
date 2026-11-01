//go:build windows

package schedule

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Ruby570bocadito/adarve/internal/probes"
)

// New devuelve el planificador del sistema.
func New() (Scheduler, error) { return taskScheduler{}, nil }

// taskScheduler usa el Programador de tareas de Windows. La ruta del
// ejecutable y la hora llegan a PowerShell por variables de entorno, nunca
// dentro del script.
type taskScheduler struct{}

const (
	taskPath = `\Adarve\`
	taskName = "Escaneo diario"
)

const psTask = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; $tp='\Adarve\'; $tn='Escaneo diario'; `

// psLegacy retira la tarea de Bastion, el nombre anterior de Adarve, que
// ejecutaría un binario antiguo (o ya desinstalado).
const psLegacy = `$o = Get-ScheduledTask -TaskPath '\Bastion\' -TaskName $tn -ErrorAction SilentlyContinue; ` +
	`if ($o) { Unregister-ScheduledTask -TaskPath '\Bastion\' -TaskName $tn -Confirm:$false }; `

func runPS(ctx context.Context, script string, env ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	exe := probes.System32(`WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.CommandContext(ctx, exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+psTask+script)
	cmd.Env = probes.PSEnviron(env...)
	b, err := cmd.CombinedOutput()
	out := string(b)
	if !utf8.Valid(b) {
		out = probes.DecodeConsole(b)
	}
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", filepath.Base(exe), err, strings.TrimSpace(out))
	}
	return out, nil
}

func (taskScheduler) Enable(ctx context.Context, exe, at string) (Status, error) {
	_, err := runPS(ctx, psLegacy+`$a = New-ScheduledTaskAction -Execute $env:ADARVE_EXE -Argument 'schedule run'; `+
		// Hora local sin desfase horario: con él, la tarea se desplaza una
		// hora tras cada cambio de horario de verano.
		`$t = New-ScheduledTaskTrigger -Daily -At $env:ADARVE_AT; $t.StartBoundary = (Get-Date $env:ADARVE_AT).ToString('s'); `+
		// También con batería: los portátiles son los que más se mueven
		// de red.
		`$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1); `+
		// SYSTEM por su SID y, si este Windows no lo admite ahí, por su
		// nombre (que no se traduce).
		`$reg = { param($u) Register-ScheduledTask -TaskPath $tp -TaskName $tn -Action $a -Trigger $t -Settings $s `+
		`-Principal (New-ScheduledTaskPrincipal -UserId $u -LogonType ServiceAccount -RunLevel Highest) `+
		`-Description 'Adarve: escaneo y superficie de ataque diarios (adarve schedule).' -Force | Out-Null }; `+
		`try { & $reg 'S-1-5-18' } catch { & $reg 'SYSTEM' }`,
		"ADARVE_EXE="+exe, "ADARVE_AT="+at)
	if err != nil {
		return Status{}, err
	}
	return taskScheduler{}.Get(ctx)
}

func (taskScheduler) Disable(ctx context.Context) error {
	_, err := runPS(ctx, psLegacy+`$t = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue; `+
		`if ($t) { Unregister-ScheduledTask -TaskPath $tp -TaskName $tn -Confirm:$false }`)
	return err
}

func (taskScheduler) Get(ctx context.Context) (Status, error) {
	out, err := runPS(ctx, `$t = Get-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue; `+
		`if (-not $t) { '{}'; return }; $i = $t | Get-ScheduledTaskInfo; `+
		`$at = ''; if ($t.Triggers.Count -gt 0 -and $t.Triggers[0].StartBoundary) { $at = ([datetime]$t.Triggers[0].StartBoundary).ToString('HH:mm') }; `+
		`@{state=[string]$t.State; at=$at; exe=[string]$t.Actions[0].Execute; args=[string]$t.Actions[0].Arguments; `+
		`next=$(if ($i.NextRunTime) { $i.NextRunTime.ToString('yyyy-MM-dd HH:mm') } else { '' }); `+
		`last=$(if ($i.LastRunTime -and $i.LastRunTime.Year -gt 2000) { $i.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { '' }); `+
		`result=[int64]$i.LastTaskResult} | ConvertTo-Json -Compress`)
	if err != nil {
		return Status{}, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var v struct {
		State, At, Exe, Args, Next, Last string
		Result                           int64
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(lines[len(lines)-1])), &v); err != nil {
		return Status{}, fmt.Errorf("respuesta inesperada del Programador de tareas: %s", strings.TrimSpace(out))
	}
	if v.Exe == "" {
		return Status{}, nil
	}
	st := Status{Enabled: !strings.EqualFold(v.State, "Disabled"), Mechanism: `Programador de tareas (` + taskPath + taskName + `)`,
		At: v.At, Command: `"` + v.Exe + `" ` + v.Args, NextRun: v.Next}
	if v.Last != "" {
		// Los fallos de la tarea son HRESULT (0x80070002: no encuentra el
		// ejecutable); los códigos de Adarve (0, 1, 3) se ven en decimal.
		code := fmt.Sprintf("%d", v.Result)
		if v.Result > 255 {
			code = fmt.Sprintf("0x%08X", uint32(v.Result)) // #nosec G115 -- HRESULT de 32 bits
		}
		st.Detail = fmt.Sprintf("última ejecución %s, código %s", v.Last, code)
	}
	return st, nil
}
