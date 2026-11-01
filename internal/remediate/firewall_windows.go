//go:build windows

package remediate

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

func init() { Register(firewallRemote{}) }

// ---- firewall.remote_address ------------------------------------------------------

// firewallRemote limita las direcciones remotas de una regla del Firewall
// de Windows. El nombre de la regla y las direcciones llegan a PowerShell
// por variables de entorno: nunca forman parte del script, así que no hay
// forma de inyectar código con un nombre de regla manipulado.
type firewallRemote struct{}

func (firewallRemote) Type() string { return "firewall.remote_address" }

// fwRule localiza la regla exacta en el almacén local (los corchetes y
// asteriscos del nombre no se toman como comodines).
const fwRule = `[Console]::OutputEncoding=[Text.Encoding]::UTF8; ` +
	`$r = @(Get-NetFirewallRule -PolicyStore PersistentStore -Name ([WildcardPattern]::Escape($env:ADARVE_FW_RULE))); ` +
	`if ($r.Count -ne 1) { throw "la regla no existe en el almacén local o no es única ($($r.Count))" }; `

func runFwPS(ctx context.Context, script string, env ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	exe := probes.System32(`WindowsPowerShell\v1.0\powershell.exe`)
	cmd := exec.CommandContext(ctx, exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+script)
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

func (firewallRemote) Capture(ctx context.Context, p probes.Params) (State, error) {
	out, err := runFwPS(ctx, fwRule+`$a = $r[0] | Get-NetFirewallAddressFilter; $pf = $r[0] | Get-NetFirewallPortFilter; `+
		`@{remote=[string]::Join(',', @($a.RemoteAddress)); display=[string]$r[0].DisplayName; `+
		`proto=[string]$pf.Protocol; ports=[string]::Join(',', @($pf.LocalPort))} | ConvertTo-Json -Compress`,
		"ADARVE_FW_RULE="+p.String("rule"))
	if err != nil {
		return nil, err
	}
	var v struct{ Remote, Display, Proto, Ports string }
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if err := json.Unmarshal([]byte(strings.TrimSpace(lines[len(lines)-1])), &v); err != nil || v.Remote == "" {
		return nil, fmt.Errorf("respuesta inesperada de Get-NetFirewallAddressFilter: %s", strings.TrimSpace(out))
	}
	if strings.EqualFold(v.Remote, p.String("remote")) {
		return skipState("la regla «" + v.Display + "» ya está limitada a " + v.Remote), nil
	}
	return State{"remote": v.Remote, "display": v.Display, "proto": v.Proto, "ports": v.Ports}, nil
}

func (firewallRemote) Describe(p probes.Params, before State) string {
	return describeFwRemote(p.String("rule"), p.String("remote"), before)
}

func (firewallRemote) Apply(ctx context.Context, p probes.Params) error {
	return setFwRemote(ctx, p.String("rule"), p.String("remote"))
}

func (firewallRemote) Restore(ctx context.Context, p probes.Params, before State) error {
	remote, _ := before["remote"].(string)
	for _, a := range strings.Split(remote, ",") {
		if !reFwAddr.MatchString(strings.TrimSpace(a)) {
			return fmt.Errorf("dirección remota no válida en la instantánea: %q", a)
		}
	}
	return setFwRemote(ctx, p.String("rule"), remote)
}

func setFwRemote(ctx context.Context, rule, remote string) error {
	_, err := runFwPS(ctx, fwRule+`$r[0] | Set-NetFirewallRule -RemoteAddress ($env:ADARVE_FW_REMOTE -split ',')`,
		"ADARVE_FW_RULE="+rule, "ADARVE_FW_REMOTE="+remote)
	return err
}
