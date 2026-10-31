//go:build windows

package remediate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Ruby570bocadito/adarve/internal/probes"
)

func init() {
	Register(registrySet{})
	Register(secpolSet{})
	Register(auditpolSet{})
	Register(serviceConfig{})
	Register(defenderASR{})
	Register(defenderPref{})
}

func run(ctx context.Context, exe string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %v: %s", filepath.Base(exe), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ---- registry.set ------------------------------------------------------------

type registrySet struct{}

func (registrySet) Type() string { return "registry.set" }

// regTarget devuelve las subrutas afectadas (expande un segmento con "*").
func regTargets(p probes.Params) ([]string, error) {
	full := strings.ReplaceAll(p.String("path"), "/", `\`)
	_, sub, _ := strings.Cut(full, `\`)
	if !strings.Contains(sub, "*") {
		return []string{sub}, nil
	}
	segs := strings.Split(sub, `\`)
	idx := -1
	for i, s := range segs {
		if strings.Contains(s, "*") {
			idx = i
			break
		}
	}
	prefix := strings.Join(segs[:idx], `\`)
	suffix := strings.Join(segs[idx+1:], `\`)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, prefix, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		if ok, _ := path.Match(strings.ToLower(segs[idx]), strings.ToLower(n)); ok {
			t := prefix + `\` + n
			if suffix != "" {
				t += `\` + suffix
			}
			out = append(out, t)
		}
	}
	return out, nil
}

func regValueType(p probes.Params) string {
	if t := strings.ToUpper(p.String("value_type")); t != "" {
		return t
	}
	if _, err := intParam(p, "value"); err == nil {
		return "DWORD"
	}
	return "SZ"
}

func (registrySet) Capture(_ context.Context, p probes.Params) (State, error) {
	targets, err := regTargets(p)
	if err != nil {
		return nil, err
	}
	name := p.String("name")
	var values []any
	for _, sub := range targets {
		entry := map[string]any{"sub": sub, "exists": false}
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, sub, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err == nil {
			_, typ, err := k.GetValue(name, nil)
			if err == nil {
				entry["exists"] = true
				switch typ {
				case registry.DWORD, registry.QWORD:
					v, _, _ := k.GetIntegerValue(name)
					entry["type"], entry["value"] = map[uint32]string{registry.DWORD: "DWORD", registry.QWORD: "QWORD"}[typ], strconv.FormatUint(v, 10)
				case registry.SZ, registry.EXPAND_SZ:
					// GetStringValue no expande las variables: se guarda el
					// texto literal y el tipo exacto para restaurarlo igual.
					v, _, _ := k.GetStringValue(name)
					entry["type"], entry["value"] = map[uint32]string{registry.SZ: "SZ", registry.EXPAND_SZ: "EXPAND_SZ"}[typ], v
				default:
					k.Close()
					return nil, fmt.Errorf("%s\\%s es de un tipo que Adarve no restaura (%d)", sub, name, typ)
				}
			}
			k.Close()
		}
		values = append(values, entry)
	}
	return State{"values": values}, nil
}

func (registrySet) Describe(p probes.Params, before State) string {
	vals, _ := before["values"].([]any)
	var olds []string
	for _, v := range vals {
		m, _ := v.(map[string]any)
		if exists, _ := m["exists"].(bool); exists {
			olds = append(olds, textOf(m["value"]))
		} else {
			olds = append(olds, "(no existe)")
		}
	}
	return fmt.Sprintf(`%s\%s: %s → %s (%s)`, p.String("path"), p.String("name"), strings.Join(olds, ", "), p.String("value"), regValueType(p))
}

func setRegValue(sub, name, typ string, value any) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, sub, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	switch typ {
	case "DWORD", "QWORD":
		n, err := strconv.ParseUint(strings.TrimSpace(fmt.Sprint(value)), 10, 64)
		if err != nil {
			return fmt.Errorf("valor %v no numérico", value)
		}
		if typ == "DWORD" {
			if n > math.MaxUint32 {
				return fmt.Errorf("valor %d no cabe en un DWORD", n)
			}
			return k.SetDWordValue(name, uint32(n))
		}
		return k.SetQWordValue(name, n)
	case "EXPAND_SZ":
		return k.SetExpandStringValue(name, fmt.Sprint(value))
	default:
		return k.SetStringValue(name, fmt.Sprint(value))
	}
}

func (registrySet) Apply(_ context.Context, p probes.Params) error {
	targets, err := regTargets(p)
	if err != nil {
		return err
	}
	value := p.String("value")
	if n, err := intParam(p, "value"); err == nil && (regValueType(p) == "DWORD" || regValueType(p) == "QWORD") {
		value = strconv.FormatInt(n, 10)
	}
	for _, sub := range targets {
		if err := setRegValue(sub, p.String("name"), regValueType(p), value); err != nil {
			return fmt.Errorf(`HKLM\%s\%s: %w`, sub, p.String("name"), err)
		}
	}
	return nil
}

func (registrySet) Restore(_ context.Context, p probes.Params, before State) error {
	vals, _ := before["values"].([]any)
	name := p.String("name")
	for _, v := range vals {
		m, _ := v.(map[string]any)
		sub := fmt.Sprint(m["sub"])
		if exists, _ := m["exists"].(bool); exists {
			if err := setRegValue(sub, name, fmt.Sprint(m["type"]), m["value"]); err != nil {
				return err
			}
			continue
		}
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, sub, registry.SET_VALUE|registry.WOW64_64KEY)
		if errors.Is(err, registry.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		err = k.DeleteValue(name)
		k.Close()
		if err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	}
	return nil
}

// ---- secpol.set -------------------------------------------------------------------

type secpolSet struct{}

func (secpolSet) Type() string { return "secpol.set" }

func (secpolSet) Capture(ctx context.Context, p probes.Params) (State, error) {
	data, err := probes.ReadSecpol(ctx)
	if err != nil {
		return nil, err
	}
	v, ok := data[strings.ToLower(p.String("section"))][strings.ToLower(p.String("key"))]
	return State{"exists": ok, "value": v}, nil
}

func (secpolSet) Describe(p probes.Params, before State) string {
	return fmt.Sprintf("directiva de seguridad %s: %s → %s", p.String("key"), textOf(before["value"]), p.String("value"))
}

// secpolConfigure aplica un valor con "secedit /configure" y una plantilla INF.
func secpolConfigure(ctx context.Context, section, key, value string) error {
	dir, err := probes.PrivateTempDir()
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	inf := fmt.Sprintf("[Unicode]\r\nUnicode=yes\r\n[%s]\r\n%s = %s\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n", section, key, value)
	u := utf16.Encode([]rune(inf))
	buf := []byte{0xFF, 0xFE}
	for _, c := range u {
		buf = append(buf, byte(c), byte(c>>8))
	}
	cfg := filepath.Join(dir, "adarve.inf")
	if err := os.WriteFile(cfg, buf, 0o600); err != nil {
		return err
	}
	_, err = run(ctx, probes.System32("secedit.exe"), "/configure", "/db", filepath.Join(dir, "adarve.sdb"),
		"/cfg", cfg, "/areas", "SECURITYPOLICY", "/quiet")
	return err
}

func (secpolSet) Apply(ctx context.Context, p probes.Params) error {
	v, _ := intParam(p, "value")
	return secpolConfigure(ctx, p.String("section"), p.String("key"), strconv.FormatInt(v, 10))
}

func (secpolSet) Restore(ctx context.Context, p probes.Params, before State) error {
	if exists, _ := before["exists"].(bool); !exists {
		return nil
	}
	return secpolConfigure(ctx, p.String("section"), p.String("key"), fmt.Sprint(before["value"]))
}

// ---- auditpol.set ------------------------------------------------------------------

type auditpolSet struct{}

func (auditpolSet) Type() string { return "auditpol.set" }

func guidArg(g string) string { return "/subcategory:{" + strings.ToUpper(strings.Trim(g, "{}")) + "}" }

func (auditpolSet) Capture(ctx context.Context, p probes.Params) (State, error) {
	data, err := probes.ReadAuditpol(ctx)
	if err != nil {
		return nil, err
	}
	s := data[strings.ToLower(strings.Trim(p.String("guid"), "{}"))]
	return State{"value": float64(s.Value), "name": s.Name}, nil
}

func (auditpolSet) Describe(p probes.Params, before State) string {
	names := map[int]string{0: "sin auditoría", 1: "aciertos", 2: "errores", 3: "aciertos y errores"}
	target := int(0)
	if p.Bool("success", false) {
		target |= 1
	}
	if p.Bool("failure", false) {
		target |= 2
	}
	old := int(before["value"].(float64))
	name := fmt.Sprint(before["name"])
	if name == "" {
		name = p.String("guid")
	}
	return fmt.Sprintf("auditoría %s: %s → %s", name, names[old], names[old|target])
}

func onOff(b bool) string {
	if b {
		return "enable"
	}
	return "disable"
}

func (auditpolSet) Apply(ctx context.Context, p probes.Params) error {
	args := []string{"/set", guidArg(p.String("guid"))}
	if p.Bool("success", false) {
		args = append(args, "/success:enable")
	}
	if p.Bool("failure", false) {
		args = append(args, "/failure:enable")
	}
	_, err := run(ctx, probes.System32("auditpol.exe"), args...)
	return err
}

func (auditpolSet) Restore(ctx context.Context, p probes.Params, before State) error {
	old := int(before["value"].(float64))
	_, err := run(ctx, probes.System32("auditpol.exe"), "/set", guidArg(p.String("guid")),
		"/success:"+onOff(old&1 != 0), "/failure:"+onOff(old&2 != 0))
	return err
}

// ---- service.config -------------------------------------------------------------------

type serviceConfig struct{}

func (serviceConfig) Type() string { return "service.config" }

var startTypes = map[string]uint32{"auto": mgr.StartAutomatic, "manual": mgr.StartManual, "disabled": mgr.StartDisabled}

func openService(name string, access uint32) (*mgr.Service, func(), error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, err
	}
	n, _ := windows.UTF16PtrFromString(name)
	h, err := windows.OpenService(scm, n, access)
	if err != nil {
		windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	s := &mgr.Service{Name: name, Handle: h}
	return s, func() { s.Close(); windows.CloseServiceHandle(scm) }, nil
}

func (serviceConfig) Capture(_ context.Context, p probes.Params) (State, error) {
	s, done, err := openService(p.String("name"), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return skipState("el servicio " + p.String("name") + " no existe"), nil
	}
	if err != nil {
		return nil, err
	}
	defer done()
	cfg, err := s.Config()
	if err != nil {
		return nil, err
	}
	st, err := s.Query()
	if err != nil {
		return nil, err
	}
	return State{"start_type": float64(cfg.StartType), "delayed": cfg.DelayedAutoStart, "running": st.State == svc.Running}, nil
}

func (serviceConfig) Describe(p probes.Params, before State) string {
	if Skipped(before) {
		return fmt.Sprintf("%s (se omite)", before["reason"])
	}
	names := map[uint32]string{0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
	verb := ""
	if p.Bool("stop", false) {
		verb = " y detener"
	}
	return fmt.Sprintf("servicio %s: %s → %s%s", p.String("name"), names[uint32(num(before["start_type"]))], p.String("start_type"), verb)
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	}
	f, _ := strconv.ParseFloat(fmt.Sprint(v), 64)
	return f
}

func setStart(name string, start uint32, delayed bool) error {
	s, done, err := openService(name, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_CHANGE_CONFIG)
	if err != nil {
		return err
	}
	defer done()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	cfg.StartType = start
	cfg.DelayedAutoStart = delayed && start == mgr.StartAutomatic
	return s.UpdateConfig(cfg)
}

func (serviceConfig) Apply(_ context.Context, p probes.Params) error {
	name := p.String("name")
	if err := setStart(name, startTypes[p.String("start_type")], false); err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		}
		return err
	}
	if !p.Bool("stop", false) {
		return nil
	}
	s, done, err := openService(name, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer done()
	st, err := s.Query()
	if err != nil || st.State == svc.Stopped {
		return err
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("no se pudo detener %s: %w", name, err)
	}
	return nil
}

func (serviceConfig) Restore(_ context.Context, p probes.Params, before State) error {
	if Skipped(before) {
		return nil
	}
	name := p.String("name")
	delayed, _ := before["delayed"].(bool)
	if err := setStart(name, uint32(num(before["start_type"])), delayed); err != nil {
		return err
	}
	if running, _ := before["running"].(bool); running {
		return startService(name)
	}
	return nil
}

// startService arranca un servicio. Si se está deteniendo (Apply acaba de
// pedirle que pare) espera a que termine; si ya está en marcha, no es error.
func startService(name string) error {
	s, done, err := openService(name, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer done()
	for deadline := time.Now().Add(30 * time.Second); ; {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Running || st.State == svc.StartPending {
			return nil
		}
		if st.State == svc.Stopped || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return nil
}

// ---- Defender ------------------------------------------------------------------------

// runPSSet ejecuta un cmdlet de Defender. Los argumentos ya están validados
// (GUID, enteros y nombres de una lista blanca) y no llevan comillas.
func runPSSet(ctx context.Context, script string) error {
	_, err := run(ctx, probes.System32(`WindowsPowerShell\v1.0\powershell.exe`),
		"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; "+script)
	return err
}

type defenderASR struct{}

func (defenderASR) Type() string { return "defender.asr" }

func asrGUID(p probes.Params) string { return strings.ToLower(strings.Trim(p.String("guid"), "{}")) }

func (defenderASR) Capture(ctx context.Context, p probes.Params) (State, error) {
	data, err := probes.QueryPS(ctx, "defender_asr")
	if err != nil {
		return nil, err
	}
	v, ok := data[asrGUID(p)]
	return State{"present": ok, "mode": num(v)}, nil
}

func (defenderASR) Describe(p probes.Params, before State) string {
	names := map[int]string{0: "desactivada", 1: "bloquear", 2: "auditar", 6: "avisar"}
	return fmt.Sprintf("regla ASR %s: %s → %s", asrGUID(p), names[int(num(before["mode"]))], names[ASRModes[p.String("mode")]])
}

func (defenderASR) Apply(ctx context.Context, p probes.Params) error {
	return runPSSet(ctx, fmt.Sprintf("Add-MpPreference -AttackSurfaceReductionRules_Ids %s -AttackSurfaceReductionRules_Actions %d",
		asrGUID(p), ASRModes[p.String("mode")]))
}

func (defenderASR) Restore(ctx context.Context, p probes.Params, before State) error {
	if present, _ := before["present"].(bool); !present {
		return runPSSet(ctx, "Remove-MpPreference -AttackSurfaceReductionRules_Ids "+asrGUID(p))
	}
	return runPSSet(ctx, fmt.Sprintf("Add-MpPreference -AttackSurfaceReductionRules_Ids %s -AttackSurfaceReductionRules_Actions %d",
		asrGUID(p), int(num(before["mode"]))))
}

type defenderPref struct{}

func (defenderPref) Type() string { return "defender.pref" }

func (defenderPref) Capture(ctx context.Context, p probes.Params) (State, error) {
	data, err := probes.QueryPS(ctx, "defender_prefs")
	if err != nil {
		return nil, err
	}
	return State{"value": num(data[p.String("name")])}, nil
}

func (defenderPref) Describe(p probes.Params, before State) string {
	return fmt.Sprintf("Defender %s: %s → %s", p.String("name"), textOf(before["value"]), p.String("value"))
}

func (defenderPref) Apply(ctx context.Context, p probes.Params) error {
	v, _ := intParam(p, "value")
	return runPSSet(ctx, fmt.Sprintf("Set-MpPreference -%s %d", p.String("name"), v))
}

func (defenderPref) Restore(ctx context.Context, p probes.Params, before State) error {
	return runPSSet(ctx, fmt.Sprintf("Set-MpPreference -%s %d", p.String("name"), int(num(before["value"]))))
}
