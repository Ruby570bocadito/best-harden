// Package rule define el formato declarativo de los controles de Adarve
// (reglas y perfiles) y su validación. Es el contrato público entre los
// paquetes de reglas y el motor de evaluación.
package rule

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity indica la gravedad de un control que no se cumple.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Severities en orden de mayor a menor gravedad.
var Severities = []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}

// Weight es el peso del control en el cálculo de la puntuación de postura.
func (s Severity) Weight() int {
	switch s {
	case SevCritical:
		return 10
	case SevHigh:
		return 5
	case SevMedium:
		return 3
	case SevLow:
		return 1
	}
	return 0
}

// Rank sirve para ordenar: 0 = más grave.
func (s Severity) Rank() int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return len(Severities)
}

func (s Severity) Valid() bool { return s.Rank() < len(Severities) }

// References vincula el control con marcos normativos y MITRE ATT&CK.
type References struct {
	NIST             []string `yaml:"nist,omitempty" json:"nist,omitempty"`
	CIS              []string `yaml:"cis,omitempty" json:"cis,omitempty"`
	STIG             []string `yaml:"stig,omitempty" json:"stig,omitempty"`
	ENS              []string `yaml:"ens,omitempty" json:"ens,omitempty"`
	MitreMitigations []string `yaml:"mitre_mitigations,omitempty" json:"mitre_mitigations,omitempty"`
	MitreTechniques  []string `yaml:"mitre_techniques,omitempty" json:"mitre_techniques,omitempty"`
	URLs             []string `yaml:"urls,omitempty" json:"urls,omitempty"`
}

// Remediation describe cómo corregir el control. En la fase 2 se añadirá la
// acción automatizada (action); por ahora es guía para el operador.
type Remediation struct {
	Summary        string `yaml:"summary" json:"summary"`
	GPO            string `yaml:"gpo,omitempty" json:"gpo,omitempty"`
	Commands       string `yaml:"commands,omitempty" json:"commands,omitempty"`
	BreakingRisk   string `yaml:"breaking_risk" json:"breaking_risk"`
	RebootRequired bool   `yaml:"reboot_required,omitempty" json:"reboot_required,omitempty"`
	// Actions son los cambios tipados que aplica "adarve harden". Si no hay,
	// la remediación es manual. Nunca existe un tipo "ejecutar comando".
	Actions []Action `yaml:"actions,omitempty" json:"actions,omitempty"`
	// Safety "remote-access" marca cambios que pueden cortar el acceso
	// remoto (SSH, RDP): se aplican con dead-man switch.
	Safety string `yaml:"safety,omitempty" json:"safety,omitempty"`
}

// Action es un cambio tipado: un tipo (registry.set, sysctl.set...) y sus
// parámetros. Ver docs/05-remediacion-segura.md.
type Action struct {
	Type   string
	Params map[string]any
}

// UnmarshalYAML separa "type" del resto de parámetros.
func (a *Action) UnmarshalYAML(n *yaml.Node) error {
	var raw map[string]any
	if err := n.Decode(&raw); err != nil {
		return err
	}
	t, _ := raw["type"].(string)
	delete(raw, "type")
	a.Type, a.Params = t, raw
	return nil
}

// MarshalJSON aplana la acción: {"type": "...", ...parámetros}.
func (a Action) MarshalJSON() ([]byte, error) {
	m := map[string]any{"type": a.Type}
	for k, v := range a.Params {
		m[k] = v
	}
	return json.Marshal(m)
}

// UnmarshalJSON es el inverso de MarshalJSON (manifiestos de cambios).
func (a *Action) UnmarshalJSON(b []byte) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	a.Type, _ = m["type"].(string)
	delete(m, "type")
	a.Params = m
	return nil
}

// RiskWave es la ola mínima en la que se aplica un riesgo de rotura:
// 1 = ninguno/bajo, 2 = medio, 3 = alto.
func RiskWave(breakingRisk string) int {
	switch breakingRisk {
	case "medium":
		return 2
	case "high":
		return 3
	}
	return 1
}

// Rule es un control de seguridad evaluable.
type Rule struct {
	ID          string      `yaml:"id" json:"id"`
	Title       string      `yaml:"title" json:"title"`
	Description string      `yaml:"description" json:"description"`
	Rationale   string      `yaml:"rationale,omitempty" json:"rationale,omitempty"`
	Category    string      `yaml:"category" json:"category"`
	Severity    Severity    `yaml:"severity" json:"severity"`
	Platforms   []string    `yaml:"platforms" json:"platforms"`
	Requires    []string    `yaml:"requires,omitempty" json:"requires,omitempty"`
	Profiles    []string    `yaml:"profiles" json:"profiles"`
	References  References  `yaml:"references" json:"references"`
	Check       Check       `yaml:"check" json:"-"`
	Remediation Remediation `yaml:"remediation" json:"remediation"`
	Impact      string      `yaml:"impact,omitempty" json:"impact,omitempty"`
	Source      string      `yaml:"-" json:"source,omitempty"`
}

// Check es una comprobación hoja (probe + operador) o compuesta (all / any).
// Los parámetros propios de cada probe (path, key, name...) van en Params.
type Check struct {
	All        []Check
	Any        []Check
	Label      string
	Probe      string
	Field      string
	Op         string
	Expected   any
	Default    any
	HasDefault bool
	OnMissing  string
	Each       string
	Params     map[string]any
}

// UnmarshalYAML separa las claves comunes de los parámetros del probe.
func (c *Check) UnmarshalYAML(n *yaml.Node) error {
	var raw map[string]yaml.Node
	if err := n.Decode(&raw); err != nil {
		return err
	}
	c.Params = map[string]any{}
	for k, v := range raw {
		v := v
		var err error
		switch k {
		case "all":
			err = v.Decode(&c.All)
		case "any":
			err = v.Decode(&c.Any)
		case "label":
			err = v.Decode(&c.Label)
		case "probe":
			err = v.Decode(&c.Probe)
		case "field":
			err = v.Decode(&c.Field)
		case "op":
			err = v.Decode(&c.Op)
		case "expected":
			err = v.Decode(&c.Expected)
		case "default":
			c.HasDefault = true
			err = v.Decode(&c.Default)
		case "on_missing":
			err = v.Decode(&c.OnMissing)
		case "each":
			err = v.Decode(&c.Each)
		default:
			var x any
			err = v.Decode(&x)
			c.Params[k] = x
		}
		if err != nil {
			return fmt.Errorf("check.%s: %w", k, err)
		}
	}
	return nil
}

// IsComposite indica si la comprobación agrupa otras.
func (c *Check) IsComposite() bool { return len(c.All) > 0 || len(c.Any) > 0 }

// Ops soportados por el motor. Ver docs/04-motor-de-reglas.md.
var Ops = map[string]bool{
	"eq": true, "ne": true, "gt": true, "gte": true, "lt": true, "lte": true,
	"between": true, "in": true, "not_in": true,
	"contains": true, "not_contains": true, "regex": true, "not_regex": true,
	"bits_set": true, "bits_clear": true, "bits_any": true,
	"mode_max": true, "exists": true, "absent": true,
}

// Platforms reconocidas en el campo platforms de las reglas.
var Platforms = map[string]bool{
	"windows": true, "windows-client": true, "windows-server": true,
	"windows-member": true, "windows-dc": true, "windows-joined": true,
	"linux": true, "linux-debian": true, "linux-ubuntu": true,
	"linux-rhel": true, "linux-fedora": true, "linux-suse": true,
	"sudo-classic": true, "sudo-rs": true,
}

var validBreakingRisk = map[string]bool{"none": true, "low": true, "medium": true, "high": true}

// Validate comprueba la regla. knownProbes y profiles permiten detectar
// referencias a probes o perfiles inexistentes.
func (r *Rule) Validate(knownProbes map[string]bool, profiles map[string]*Profile, validateAction func(Action) error) []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if !validID(r.ID) {
		add("id %q inválido: usa el formato PLATAFORMA-CATEGORÍA-NNN (p. ej. LNX-SSH-001)", r.ID)
	}
	if strings.TrimSpace(r.Title) == "" {
		add("title vacío")
	}
	if strings.TrimSpace(r.Description) == "" {
		add("description vacía")
	}
	if r.Category == "" {
		add("category vacía")
	}
	if !r.Severity.Valid() {
		add("severity %q inválida (critical|high|medium|low|info)", r.Severity)
	}
	if len(r.Platforms) == 0 {
		add("platforms vacío")
	}
	for _, p := range r.Platforms {
		if !Platforms[p] {
			add("platform %q desconocida", p)
		}
	}
	for _, p := range r.Requires {
		if !Platforms[p] {
			add("requires %q desconocido", p)
		}
	}
	if len(r.Profiles) == 0 {
		add("profiles vacío: la regla no se usaría en ningún perfil")
	}
	for _, p := range r.Profiles {
		if profiles != nil && profiles[p] == nil {
			add("profile %q no existe", p)
		}
	}
	if strings.TrimSpace(r.Remediation.Summary) == "" {
		add("remediation.summary vacío")
	}
	if !validBreakingRisk[r.Remediation.BreakingRisk] {
		add("remediation.breaking_risk %q inválido (none|low|medium|high)", r.Remediation.BreakingRisk)
	}
	switch r.Remediation.Safety {
	case "", "remote-access":
	default:
		add("remediation.safety %q inválido (remote-access)", r.Remediation.Safety)
	}
	for i, a := range r.Remediation.Actions {
		if a.Type == "" {
			add("remediation.actions[%d]: falta type", i)
			continue
		}
		if ActionOS != nil {
			if os := ActionOS(a.Type); os != "" {
				for _, p := range r.Platforms {
					if platformOS(p) != os {
						add("remediation.actions[%d] (%s): solo existe en %s y la regla es para %s", i, a.Type, os, p)
					}
				}
			}
		}
		if validateAction != nil {
			if err := validateAction(a); err != nil {
				add("remediation.actions[%d] (%s): %v", i, a.Type, err)
			}
		}
	}
	errs = append(errs, validateCheck(&r.Check, knownProbes, "check")...)
	return errs
}

// ActionOS devuelve el sistema ("windows", "linux") en el que existe un tipo
// de acción, o "" si no se sabe. Lo fija el paquete de remediación; si es
// nil no se comprueba.
var ActionOS func(actionType string) string

// platformOS es el sistema de una etiqueta de plataforma.
func platformOS(p string) string {
	if strings.HasPrefix(p, "windows") {
		return "windows"
	}
	if strings.HasPrefix(p, "linux") {
		return "linux"
	}
	return p
}

// ProbeParams son los parámetros que admite cada probe oficial (mantener
// sincronizado con internal/probes). Un parámetro desconocido suele ser una
// errata (p. ej. "on_mising") que, si no, se ignoraría en silencio. Los
// probes que no aparecen aquí (de terceros o de pruebas) no se comprueban.
var ProbeParams = map[string][]string{
	"file_content": {"path"},
	"file_regex":   {"path", "pattern", "ignore_comments"},
	"file_kv":      {"path", "key", "separator", "case_insensitive"},
	"sysctl":       {"key"},
	"file":         {"path"},
	"sshd":         {"key"},
	"kmod":         {"name"},
	"systemd":      {"unit"},
	"mount":        {"path"},
	"package":      {"name"},
	"registry":     {"path", "name"},
	"secpol":       {"section", "key"},
	"auditpol":     {"guid"},
	"service":      {"name"},
	"ps":           {"query"},
}

func validateCheck(c *Check, knownProbes map[string]bool, path string) []error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(path+": "+format, a...)) }

	kinds := 0
	if c.Probe != "" {
		kinds++
	}
	if len(c.All) > 0 {
		kinds++
	}
	if len(c.Any) > 0 {
		kinds++
	}
	if kinds != 1 {
		add("debe tener exactamente uno de: probe, all, any")
		return errs
	}
	for i := range c.All {
		errs = append(errs, validateCheck(&c.All[i], knownProbes, fmt.Sprintf("%s.all[%d]", path, i))...)
	}
	for i := range c.Any {
		errs = append(errs, validateCheck(&c.Any[i], knownProbes, fmt.Sprintf("%s.any[%d]", path, i))...)
	}
	if c.Probe == "" {
		// Una comprobación compuesta solo agrupa: lo demás se ignoraría.
		if c.Op != "" || c.Expected != nil || c.HasDefault || c.OnMissing != "" || c.Each != "" || c.Field != "" || len(c.Params) > 0 {
			add("una comprobación all/any solo admite label y sus hijos (op, expected, field, default, on_missing, each y los parámetros van en cada hijo)")
		}
		return errs
	}
	if knownProbes != nil && !knownProbes[c.Probe] {
		add("probe %q desconocido", c.Probe)
	}
	if allowed, ok := ProbeParams[c.Probe]; ok {
		for _, k := range sortedKeys(c.Params) {
			if !contains(allowed, k) {
				add("parámetro %q desconocido para el probe %s (admite: %s)", k, c.Probe, strings.Join(allowed, ", "))
			}
		}
	}
	if !Ops[c.Op] {
		add("op %q inválido", c.Op)
	}
	if c.Op != "exists" && c.Op != "absent" && c.Expected == nil {
		add("falta expected")
	}
	switch c.Op {
	case "regex", "not_regex":
		if _, err := regexp.Compile(fmt.Sprint(c.Expected)); err != nil {
			add("expected no es una expresión regular válida: %v", err)
		}
	case "between":
		if l, ok := c.Expected.([]any); !ok || len(l) != 2 {
			add("between necesita expected: [mín, máx]")
		}
	case "mode_max":
		if _, err := strconv.ParseUint(strings.TrimSpace(fmt.Sprint(c.Expected)), 8, 32); err != nil {
			add("mode_max necesita permisos octales como \"0600\"")
		}
	}
	switch c.OnMissing {
	case "", "fail", "pass", "na":
	default:
		add("on_missing %q inválido (fail|pass|na)", c.OnMissing)
	}
	switch c.Each {
	case "", "all", "any":
	default:
		add("each %q inválido (all|any)", c.Each)
	}
	return errs
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ValidID indica si id tiene el formato de ID de regla
// (PLATAFORMA-CATEGORÍA-NNN: al menos tres partes de mayúsculas y dígitos).
func ValidID(id string) bool { return validID(id) }

func validID(id string) bool {
	parts := strings.Split(id, "-")
	if len(parts) < 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, r := range p {
			if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
				return false
			}
		}
	}
	return true
}

// RequirementMessages explica por qué una regla con requires no aplica.
var RequirementMessages = map[string]string{
	"windows-joined": "solo aplica a equipos unidos a un dominio de Active Directory o a Entra ID",
	"sudo-classic":   "solo aplica al sudo clásico (con sudo-rs, la opción no existe o la cubre otro control)",
	"sudo-rs":        "solo aplica a sudo-rs (con el sudo clásico lo cubre otro control)",
}

// MissingRequirement devuelve el primer requisito de la regla que el equipo
// no cumple, o "" si los cumple todos.
func (r *Rule) MissingRequirement(hostTags []string) string {
	for _, req := range r.Requires {
		found := false
		for _, t := range hostTags {
			if t == req {
				found = true
				break
			}
		}
		if !found {
			return req
		}
	}
	return ""
}

// Profile agrupa reglas para un rol (estación de trabajo, servidor, DC...).
type Profile struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Platforms   []string `yaml:"platforms" json:"platforms"`
	Extends     []string `yaml:"extends,omitempty" json:"extends,omitempty"`
	DefaultFor  []string `yaml:"default_for,omitempty" json:"default_for,omitempty"`
	Source      string   `yaml:"-" json:"-"`
}

// MatchesPlatform indica si alguna de las etiquetas del equipo está en list.
func MatchesPlatform(list, hostTags []string) bool {
	for _, p := range list {
		for _, t := range hostTags {
			if p == t {
				return true
			}
		}
	}
	return false
}

// SortRules ordena por severidad y después por ID.
func SortRules(rs []*Rule) {
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Severity.Rank() != rs[j].Severity.Rank() {
			return rs[i].Severity.Rank() < rs[j].Severity.Rank()
		}
		return rs[i].ID < rs[j].ID
	})
}
