// Package remediate aplica los cambios de hardening de forma transaccional:
// captura el estado previo, aplica, verifica y revierte si algo falla.
//
// Principios (ver docs/05-remediacion-segura.md y ADR-0004):
//   - Solo existen acciones TIPADAS (registry.set, sysctl.set...). No hay ni
//     habrá un tipo "ejecutar comando".
//   - Los parámetros se validan estrictamente (listas blancas y expresiones
//     regulares) antes de usarse, también en "bastion rules lint".
//   - Cada acción sabe capturar el estado previo y restaurarlo.
package remediate

import (
	"context"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// State es el estado previo de un elemento. Se guarda en el manifiesto del
// cambio (JSON) para poder restaurarlo, incluso desde otro proceso.
type State map[string]any

// Remediator aplica y revierte un tipo de acción.
type Remediator interface {
	Type() string
	// Capture lee el estado actual (solo lectura).
	Capture(ctx context.Context, p probes.Params) (State, error)
	// Describe explica el cambio: "elemento: antes → después".
	Describe(p probes.Params, before State) string
	Apply(ctx context.Context, p probes.Params) error
	Restore(ctx context.Context, p probes.Params, before State) error
}

var (
	regMu        sync.RWMutex
	remediators  = map[string]Remediator{}
	errSkipState = "skip"
)

// Register registra un remediador disponible en esta plataforma.
func Register(r Remediator) {
	regMu.Lock()
	defer regMu.Unlock()
	remediators[r.Type()] = r
}

// Get devuelve el remediador de un tipo, si existe en esta plataforma.
func Get(t string) (Remediator, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	r, ok := remediators[t]
	return r, ok
}

func init() {
	// "bastion rules lint" comprueba que cada acción existe en la plataforma
	// de la regla (un registry.set en una regla de Linux nunca se aplicaría).
	rule.ActionOS = func(t string) string { return Specs[t].OS }
}

// Skipped indica que la captura decidió que no hay nada que hacer (p. ej. un
// parámetro sysctl de IPv6 en un equipo sin IPv6, marcado como optional).
func Skipped(s State) bool { b, _ := s[errSkipState].(bool); return b }

func skipState(reason string) State { return State{errSkipState: true, "reason": reason} }

// ---- Especificación y validación de acciones (independiente del SO) -----

// Spec describe un tipo de acción para validarla en cualquier plataforma.
type Spec struct {
	OS       string
	Required []string
	// Optional son los demás parámetros admitidos; cualquier otro es un
	// error (una errata como "optinal" se ignoraría en silencio).
	Optional []string
	// Bools son los parámetros (opcionales) que deben ser booleanos.
	Bools    []string
	Validate func(p probes.Params) error
}

var (
	reGUID     = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	reSysctl   = regexp.MustCompile(`^[a-z0-9_]+(\.[a-zA-Z0-9_-]+)+$`)
	reWord     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
	reKVKey    = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	reModule   = regexp.MustCompile(`^[a-z0-9_-]+$`)
	reUnit     = regexp.MustCompile(`^[A-Za-z0-9@._-]+\.(service|socket|timer|path)$`)
	reService  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	reOctal    = regexp.MustCompile(`^0?[0-7]{3,4}$`)
	reAccount  = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)
	reSafeText = regexp.MustCompile(`^[^\r\n\x00]*$`)
)

// SecpolKeys son las claves de [System Access] que Bastion puede modificar.
var SecpolKeys = map[string]bool{
	"MinimumPasswordLength": true, "PasswordComplexity": true, "PasswordHistorySize": true,
	"MaximumPasswordAge": true, "MinimumPasswordAge": true, "ClearTextPassword": true,
	"LockoutBadCount": true, "LockoutDuration": true, "ResetLockoutCount": true,
	"EnableGuestAccount": true, "LSAAnonymousNameLookup": true,
}

// DefenderPrefs son las preferencias de Defender que Bastion puede modificar.
var DefenderPrefs = map[string]bool{
	"PUAProtection": true, "MAPSReporting": true, "EnableNetworkProtection": true, "SubmitSamplesConsent": true,
}

// ASRModes traduce el modo de una regla ASR a su valor numérico.
var ASRModes = map[string]int{"disabled": 0, "block": 1, "audit": 2, "warn": 6}

// SudoersOptions son las opciones "Defaults" que Bastion puede añadir.
var SudoersOptions = map[string]bool{
	"use_pty": true, `logfile="/var/log/sudo.log"`: true,
}

// Specs son todos los tipos de acción conocidos.
var Specs = map[string]Spec{
	"registry.set": {OS: "windows", Required: []string{"path", "name", "value"}, Optional: []string{"value_type"}, Validate: func(p probes.Params) error {
		path := strings.ToUpper(p.String("path"))
		if !strings.HasPrefix(path, `HKLM\`) && !strings.HasPrefix(path, `HKEY_LOCAL_MACHINE\`) {
			return fmt.Errorf("solo se admiten rutas HKLM")
		}
		vt := strings.ToUpper(p.String("value_type"))
		if f, ok := p["value"].(float64); ok && f != math.Trunc(f) {
			return fmt.Errorf("value %v no es entero (para texto usa comillas y value_type: SZ)", f)
		}
		switch vt {
		case "", "DWORD", "QWORD":
			n, err := intParam(p, "value")
			if err != nil {
				if vt != "" {
					return err
				}
				break // sin value_type y no numérico: REG_SZ
			}
			if n < 0 {
				return fmt.Errorf("value %d negativo: usa el valor sin signo (p. ej. 4294967295 en vez de -1)", n)
			}
			if vt != "QWORD" && n > math.MaxUint32 {
				return fmt.Errorf("value %d no cabe en un DWORD (usa value_type: QWORD)", n)
			}
		case "SZ", "EXPAND_SZ":
		default:
			return fmt.Errorf("value_type %q no soportado (DWORD, QWORD, SZ, EXPAND_SZ)", p.String("value_type"))
		}
		return safeText(p, "path", "name", "value")
	}},
	"secpol.set": {OS: "windows", Required: []string{"section", "key", "value"}, Validate: func(p probes.Params) error {
		if p.String("section") != "System Access" {
			return fmt.Errorf("solo se admite la sección \"System Access\"")
		}
		if !SecpolKeys[p.String("key")] {
			return fmt.Errorf("clave %q no permitida", p.String("key"))
		}
		_, err := intParam(p, "value")
		return err
	}},
	"auditpol.set": {OS: "windows", Required: []string{"guid"}, Optional: []string{"success", "failure"}, Bools: []string{"success", "failure"}, Validate: func(p probes.Params) error {
		if !reGUID.MatchString(p.String("guid")) {
			return fmt.Errorf("guid inválido")
		}
		if !p.Bool("success", false) && !p.Bool("failure", false) {
			return fmt.Errorf("indica success y/o failure")
		}
		return nil
	}},
	"service.config": {OS: "windows", Required: []string{"name", "start_type"}, Optional: []string{"stop"}, Bools: []string{"stop"}, Validate: func(p probes.Params) error {
		if !reService.MatchString(p.String("name")) {
			return fmt.Errorf("nombre de servicio inválido")
		}
		switch p.String("start_type") {
		case "disabled", "manual", "auto":
			return nil
		}
		return fmt.Errorf("start_type debe ser disabled, manual o auto")
	}},
	"defender.asr": {OS: "windows", Required: []string{"guid", "mode"}, Validate: func(p probes.Params) error {
		if !reGUID.MatchString(p.String("guid")) {
			return fmt.Errorf("guid inválido")
		}
		if _, ok := ASRModes[p.String("mode")]; !ok {
			return fmt.Errorf("mode debe ser block, audit, warn o disabled")
		}
		return nil
	}},
	"defender.pref": {OS: "windows", Required: []string{"name", "value"}, Validate: func(p probes.Params) error {
		if !DefenderPrefs[p.String("name")] {
			return fmt.Errorf("preferencia %q no permitida", p.String("name"))
		}
		v, err := intParam(p, "value")
		if err != nil || v < 0 || v > 6 {
			return fmt.Errorf("value debe ser un entero entre 0 y 6")
		}
		return nil
	}},
	"sysctl.set": {OS: "linux", Required: []string{"key", "value"}, Optional: []string{"optional"}, Bools: []string{"optional"}, Validate: func(p probes.Params) error {
		if !reSysctl.MatchString(p.String("key")) || strings.Contains(p.String("key"), "..") {
			return fmt.Errorf("clave sysctl inválida")
		}
		return safeText(p, "value")
	}},
	"sshd.set": {OS: "linux", Required: []string{"key", "value"}, Validate: func(p probes.Params) error {
		if !reWord.MatchString(p.String("key")) {
			return fmt.Errorf("opción de sshd inválida")
		}
		if strings.ToLower(p.String("key")) == "include" || strings.ToLower(p.String("key")) == "match" {
			return fmt.Errorf("las directivas Include y Match no se pueden gestionar")
		}
		return safeText(p, "value")
	}},
	"kmod.block": {OS: "linux", Required: []string{"name"}, Validate: func(p probes.Params) error {
		if !reModule.MatchString(p.String("name")) {
			return fmt.Errorf("nombre de módulo inválido")
		}
		return nil
	}},
	"systemd.disable": {OS: "linux", Required: []string{"unit"}, Optional: []string{"mask"}, Bools: []string{"mask"}, Validate: func(p probes.Params) error {
		if !reUnit.MatchString(p.String("unit")) {
			return fmt.Errorf("unidad inválida")
		}
		return nil
	}},
	"file.mode": {OS: "linux", Required: []string{"path", "mode"}, Optional: []string{"owner", "group"}, Validate: func(p probes.Params) error {
		for _, path := range p.Strings("path") {
			if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
				return fmt.Errorf("ruta %q no absoluta", path)
			}
		}
		if !reOctal.MatchString(p.String("mode")) {
			return fmt.Errorf("mode debe ser octal, p. ej. \"0600\"")
		}
		for _, k := range []string{"owner", "group"} {
			for _, v := range p.Strings(k) {
				if !reAccount.MatchString(v) {
					return fmt.Errorf("%s %q inválido", k, v)
				}
			}
		}
		return nil
	}},
	"file.kv_set": {OS: "linux", Required: []string{"path", "key", "value"}, Optional: []string{"separator"}, Validate: func(p probes.Params) error {
		if !strings.HasPrefix(p.String("path"), "/etc/") || strings.Contains(p.String("path"), "..") {
			return fmt.Errorf("solo se admiten ficheros bajo /etc")
		}
		if !reKVKey.MatchString(p.String("key")) {
			return fmt.Errorf("clave inválida")
		}
		return safeText(p, "value", "separator")
	}},
	// Limita a la red local una regla del Firewall de Windows por su nombre
	// interno (lo usa "bastion surface fix", no las reglas del catálogo).
	"firewall.remote_address": {OS: "windows", Required: []string{"rule", "remote"}, Validate: func(p probes.Params) error {
		if p.String("remote") != "LocalSubnet" {
			return fmt.Errorf("remote solo admite LocalSubnet")
		}
		if r := p.String("rule"); strings.TrimSpace(r) == "" || len(r) > 1024 {
			return fmt.Errorf("rule debe ser el nombre interno de una regla del firewall")
		}
		return safeText(p, "rule")
	}},
	"sudoers.defaults": {OS: "linux", Required: []string{"option"}, Validate: func(p probes.Params) error {
		if !SudoersOptions[p.String("option")] {
			return fmt.Errorf("opción %q no permitida", p.String("option"))
		}
		return nil
	}},
}

// ValidateAction comprueba el tipo y los parámetros de una acción.
func ValidateAction(a rule.Action) error {
	spec, ok := Specs[a.Type]
	if !ok {
		types := make([]string, 0, len(Specs))
		for t := range Specs {
			types = append(types, t)
		}
		sort.Strings(types)
		return fmt.Errorf("tipo desconocido (válidos: %s)", strings.Join(types, ", "))
	}
	p := probes.Params(a.Params)
	if err := p.Require(spec.Required...); err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, spec.Required...), spec.Optional...) {
		allowed[k] = true
	}
	var unknown []string
	for k := range p {
		if !allowed[k] {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("parámetros desconocidos: %s", strings.Join(unknown, ", "))
	}
	for _, k := range spec.Bools {
		switch v := p[k].(type) {
		case nil, bool:
		case string:
			if _, err := strconv.ParseBool(v); err != nil {
				return fmt.Errorf("%s debe ser true o false", k)
			}
		default:
			return fmt.Errorf("%s debe ser true o false", k)
		}
	}
	if spec.Validate != nil {
		return spec.Validate(p)
	}
	return nil
}

func safeText(p probes.Params, keys ...string) error {
	for _, k := range keys {
		for _, v := range p.Strings(k) {
			if !reSafeText.MatchString(v) {
				return fmt.Errorf("%s contiene saltos de línea o caracteres no permitidos", k)
			}
		}
	}
	return nil
}

// intParam lee un parámetro entero (YAML lo entrega como int; JSON, como
// float64). Rechaza decimales y valores fuera de rango en vez de truncarlos.
func intParam(p probes.Params, key string) (int64, error) {
	switch v := p[key].(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case uint64:
		if v > math.MaxInt64 {
			return 0, fmt.Errorf("%s fuera de rango", key)
		}
		return int64(v), nil
	case float64:
		if v != math.Trunc(v) || v >= math.MaxInt64 || v < math.MinInt64 {
			return 0, fmt.Errorf("%s debe ser un número entero", key)
		}
		return int64(v), nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err == nil {
			return n, nil
		}
	}
	return 0, fmt.Errorf("%s debe ser un número entero", key)
}

// textOf representa un valor de estado para Describe.
func textOf(v any) string {
	switch x := v.(type) {
	case nil:
		return "—"
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
	}
	return fmt.Sprint(v)
}

// ---- Validación del estado previo guardado en un manifiesto ---------------

// reFwAddr valida cada dirección remota guardada en una instantánea antes de
// restaurarla: IP, subred, rango o palabra clave (Any, LocalSubnet…).
var reFwAddr = regexp.MustCompile(`^[A-Za-z0-9.:/-]+$`)

// stateNum lee un número de un estado (JSON lo entrega como float64).
func stateNum(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint32:
		return float64(x), true
	case uint64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	}
	return 0, false
}

func stateInt(before State, key string, lo, hi float64) error {
	n, ok := stateNum(before[key])
	if !ok || n != math.Trunc(n) || n < lo || n > hi {
		return fmt.Errorf("%s = %v fuera de rango", key, before[key])
	}
	return nil
}

// regSubMatches indica si la subclave guardada corresponde a la ruta de la
// acción (con su comodín, si lo tiene).
func regSubMatches(actionPath, sub string) bool {
	full := strings.ReplaceAll(actionPath, "/", `\`)
	_, pattern, _ := strings.Cut(full, `\`)
	ps, ss := strings.Split(pattern, `\`), strings.Split(sub, `\`)
	if len(ps) != len(ss) {
		return false
	}
	for i := range ps {
		if strings.Contains(ps[i], "*") {
			if ok, _ := path.Match(strings.ToLower(ps[i]), strings.ToLower(ss[i])); !ok {
				return false
			}
			continue
		}
		if !strings.EqualFold(ps[i], ss[i]) {
			return false
		}
	}
	return true
}

// ValidateBefore comprueba que el estado previo de una entrada del manifiesto
// solo puede restaurar lo que la propia acción toca. El manifiesto se lee de
// disco: sin esto, un manifiesto manipulado convertiría "bastion rollback" en
// una escritura arbitraria (cualquier clave HKLM, chmod de cualquier
// fichero, líneas inyectadas en la plantilla de secedit...).
func ValidateBefore(a rule.Action, before State) error {
	if before == nil {
		return fmt.Errorf("sin estado previo")
	}
	if Skipped(before) {
		return nil
	}
	p := probes.Params(a.Params)
	switch a.Type {
	case "registry.set":
		vals, ok := before["values"].([]any)
		if !ok {
			return fmt.Errorf("values ausente")
		}
		for _, v := range vals {
			m, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("valor de registro mal formado")
			}
			sub, _ := m["sub"].(string)
			if !regSubMatches(p.String("path"), sub) || !reSafeText.MatchString(sub) {
				return fmt.Errorf("la subclave %q no corresponde a %s", sub, p.String("path"))
			}
			if exists, _ := m["exists"].(bool); !exists {
				continue
			}
			switch t := fmt.Sprint(m["type"]); t {
			case "DWORD", "QWORD":
				n, err := strconv.ParseUint(strings.TrimSpace(fmt.Sprint(m["value"])), 10, 64)
				if err != nil || (t == "DWORD" && n > math.MaxUint32) {
					return fmt.Errorf("valor %v no válido para %s", m["value"], t)
				}
			case "SZ", "EXPAND_SZ":
				if strings.ContainsRune(fmt.Sprint(m["value"]), 0) {
					return fmt.Errorf("valor de texto con caracteres nulos")
				}
			default:
				return fmt.Errorf("tipo de registro %q no restaurable", t)
			}
		}
	case "secpol.set":
		if exists, _ := before["exists"].(bool); exists {
			if _, err := strconv.ParseInt(strings.TrimSpace(fmt.Sprint(before["value"])), 10, 64); err != nil {
				return fmt.Errorf("valor de directiva %q no entero", fmt.Sprint(before["value"]))
			}
		}
	case "auditpol.set":
		return stateInt(before, "value", 0, 3)
	case "service.config":
		return stateInt(before, "start_type", 0, 4)
	case "defender.asr":
		if present, _ := before["present"].(bool); present {
			n, ok := stateNum(before["mode"])
			if !ok {
				return fmt.Errorf("modo ASR no numérico")
			}
			valid := false
			for _, v := range ASRModes {
				if float64(v) == n {
					valid = true
				}
			}
			if !valid {
				return fmt.Errorf("modo ASR %v no válido", n)
			}
		}
	case "defender.pref":
		return stateInt(before, "value", 0, 6)
	case "file.mode":
		path, _ := before["path"].(string)
		found := false
		for _, x := range p.Strings("path") {
			if x == path {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("la ruta %q no es la de la acción", path)
		}
		if err := stateInt(before, "mode", 0, 0o7777); err != nil {
			return err
		}
		if _, ok := before["uid"]; ok {
			if err := stateInt(before, "uid", 0, math.MaxUint32); err != nil {
				return err
			}
			if err := stateInt(before, "gid", 0, math.MaxUint32); err != nil {
				return err
			}
		}
	case "sysctl.set":
		if rt, ok := before["runtime"].(string); ok && !reSafeText.MatchString(rt) {
			return fmt.Errorf("valor sysctl con saltos de línea")
		}
		if f, ok := before["file"].(map[string]any); ok {
			if err := validateFileState(State(f)); err != nil {
				return err
			}
		}
	case "kmod.block":
		if f, ok := before["file"].(map[string]any); ok {
			return validateFileState(State(f))
		}
	case "sshd.set", "file.kv_set", "sudoers.defaults":
		return validateFileState(before)
	case "firewall.remote_address":
		remote, _ := before["remote"].(string)
		for _, a := range strings.Split(remote, ",") {
			if !reFwAddr.MatchString(strings.TrimSpace(a)) {
				return fmt.Errorf("dirección remota no válida en la instantánea: %q", a)
			}
		}
	}
	return nil
}

// validateFileState comprueba el estado de un fichero capturado (contenido,
// permisos y propietario); la ruta la fija siempre la acción, no el estado.
func validateFileState(s State) error {
	if exists, _ := s["exists"].(bool); !exists {
		return nil
	}
	if _, ok := s["content"].(string); !ok {
		return fmt.Errorf("contenido ausente")
	}
	if err := stateInt(s, "mode", 0, 0o7777); err != nil {
		return err
	}
	if _, ok := s["uid"]; ok {
		if err := stateInt(s, "uid", 0, math.MaxUint32); err != nil {
			return err
		}
		if err := stateInt(s, "gid", 0, math.MaxUint32); err != nil {
			return err
		}
	}
	return nil
}
