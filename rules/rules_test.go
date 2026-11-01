package rules_test

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/Ruby570bocadito/adarve/internal/probes"
	"github.com/Ruby570bocadito/adarve/internal/remediate"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
	"github.com/Ruby570bocadito/adarve/rules"
)

// TestOfficialPack valida todas las reglas y perfiles incrustados. Es la red
// de seguridad de CI: una regla mal escrita nunca llega a una release.
func TestOfficialPack(t *testing.T) {
	c := rule.NewCatalog()
	if err := c.LoadFS(rules.FS, "rules/"); err != nil {
		t.Fatalf("carga: %v", err)
	}
	for _, err := range c.Validate(probes.KnownSet(), remediate.ValidateAction) {
		t.Error(err)
	}
	if len(c.Rules) < 100 {
		t.Errorf("se esperaban al menos 100 reglas, hay %d", len(c.Rules))
	}
	// Cada perfil por defecto debe tener reglas para su plataforma.
	for _, tags := range [][]string{
		{"linux-ubuntu", "linux-debian", "linux"},
		{"linux-rocky", "linux-rhel", "linux"},
		{"windows-client", "windows"},
		{"windows-member", "windows-server", "windows"},
		{"windows-dc", "windows-server", "windows"},
	} {
		p := c.DefaultProfile(tags)
		if p == nil {
			t.Errorf("sin perfil por defecto para %v", tags)
			continue
		}
		if n := len(c.Select(tags, p.ID)); n < 20 {
			t.Errorf("perfil %s: solo %d reglas para %v", p.ID, n, tags)
		}
	}
}

func TestDCInheritsServerBaseline(t *testing.T) {
	c := rule.NewCatalog()
	if err := c.LoadFS(rules.FS, "rules/"); err != nil {
		t.Fatal(err)
	}
	dc := []string{"windows-dc", "windows-server", "windows"}
	ids := map[string]bool{}
	for _, r := range c.Select(dc, "win-dc-l1") {
		ids[r.ID] = true
	}
	for _, want := range []string{"WIN-DC-001", "WIN-NET-001", "WIN-CRED-001"} {
		if !ids[want] {
			t.Errorf("win-dc-l1 debería incluir %s", want)
		}
	}
	if ids["WIN-ACC-006"] {
		t.Error("LAPS no aplica a controladores de dominio")
	}
}

// El esquema JSON (validación en el editor) debe admitir actions/safety y
// conocer los mismos tipos de acción que el motor de remediación.
func TestSchemaActionTypes(t *testing.T) {
	b, err := os.ReadFile("schema/rule.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Properties struct {
			Remediation struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"remediation"`
		} `json:"properties"`
		Defs struct {
			Action struct {
				Properties struct {
					Type struct {
						Enum []string `json:"enum"`
					} `json:"type"`
				} `json:"properties"`
			} `json:"action"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"actions", "safety"} {
		if _, ok := s.Properties.Remediation.Properties[k]; !ok {
			t.Errorf("el esquema no declara remediation.%s", k)
		}
	}
	got := map[string]bool{}
	for _, e := range s.Defs.Action.Properties.Type.Enum {
		got[e] = true
	}
	for typ := range remediate.Specs {
		if !got[typ] {
			t.Errorf("el esquema no conoce la acción %s", typ)
		}
	}
	if len(got) != len(remediate.Specs) {
		t.Errorf("el esquema tiene %d tipos de acción y el motor %d", len(got), len(remediate.Specs))
	}
}

// Los controles de use_pty: LNX-AUTH-006 (sudo clásico) busca la opción y
// LNX-AUTH-009 (sudo-rs, donde está activada por defecto) busca que alguien
// la desactive. Las dos se evalúan línea a línea, sin los comentarios.
func TestSudoPTYPatterns(t *testing.T) {
	c := rule.NewCatalog()
	if err := c.LoadFS(rules.FS, "rules/"); err != nil {
		t.Fatalf("carga: %v", err)
	}
	pattern := func(id string) *regexp.Regexp {
		r := c.Rule(id)
		if r == nil {
			t.Fatalf("no existe %s", id)
		}
		return regexp.MustCompile(r.Check.Params["pattern"].(string))
	}
	enable, disable := pattern("LNX-AUTH-006"), pattern("LNX-AUTH-009")
	for line, want := range map[string][2]bool{ // [activa use_pty, lo desactiva]
		"Defaults use_pty":                        {true, false},
		"Defaults\tenv_reset, use_pty":            {true, false},
		"Defaults !use_pty":                       {false, true},
		"Defaults ! use_pty":                      {false, true},
		"Defaults env_reset,!use_pty":             {false, true},
		"Defaults env_reset, timestamp_timeout=5": {false, false},
		"Defaults:alice !use_pty":                 {false, false}, // por usuario: fuera del alcance de ambos controles
		"Defaults use_ptyx":                       {false, false},
	} {
		if got := enable.MatchString(line); got != want[0] {
			t.Errorf("LNX-AUTH-006 con %q: %v, quiero %v", line, got, want[0])
		}
		if got := disable.MatchString(line); got != want[1] {
			t.Errorf("LNX-AUTH-009 con %q: %v, quiero %v", line, got, want[1])
		}
	}
	if r := c.Rule("LNX-AUTH-006"); r.MissingRequirement([]string{"linux", "sudo-rs"}) == "" {
		t.Error("LNX-AUTH-006 no debe aplicarse con sudo-rs")
	}
	if r := c.Rule("LNX-AUTH-009"); r.MissingRequirement([]string{"linux", "sudo-classic"}) == "" {
		t.Error("LNX-AUTH-009 no debe aplicarse con el sudo clásico")
	}
	if r := c.Rule("LNX-AUTH-007"); r.MissingRequirement([]string{"linux", "sudo-rs"}) == "" {
		t.Error("LNX-AUTH-007 (logfile) no debe aplicarse con sudo-rs")
	}
}

// El esquema JSON de las reglas (validación en el editor y referencia del
// formato v1) debe aceptar exactamente lo que acepta el código: plataformas,
// requisitos, probes, operadores y tipos de acción. Si el código añade uno y
// el esquema no, los editores marcarían como inválida una regla correcta.
func TestRuleSchemaMatchesCode(t *testing.T) {
	b, err := os.ReadFile("schema/rule.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	type enum struct {
		Enum []string `json:"enum"`
	}
	var s struct {
		Properties struct {
			Platforms struct {
				Items enum `json:"items"`
			} `json:"platforms"`
			Requires struct {
				Items enum `json:"items"`
			} `json:"requires"`
		} `json:"properties"`
		Defs struct {
			Action struct {
				Properties struct {
					Type enum `json:"type"`
				} `json:"properties"`
			} `json:"action"`
			Check struct {
				Properties struct {
					Probe enum `json:"probe"`
					Op    enum `json:"op"`
				} `json:"properties"`
			} `json:"check"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	set := func(xs []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	same := func(what string, schema, code map[string]bool) {
		t.Helper()
		for k := range code {
			if !schema[k] {
				t.Errorf("%s: el código admite %q y el esquema no", what, k)
			}
		}
		for k := range schema {
			if !code[k] {
				t.Errorf("%s: el esquema admite %q y el código no", what, k)
			}
		}
	}
	requires := map[string]bool{}
	for k := range rule.RequirementMessages {
		requires[k] = true
	}
	same("requires", set(s.Properties.Requires.Items.Enum), requires)
	// platforms y requires comparten el mismo conjunto de etiquetas en el código.
	tags := set(s.Properties.Platforms.Items.Enum)
	for k := range requires {
		tags[k] = true
	}
	same("platforms y requires", tags, rule.Platforms)
	same("check.probe", set(s.Defs.Check.Properties.Probe.Enum), probes.KnownSet())
	same("check.op", set(s.Defs.Check.Properties.Op.Enum), rule.Ops)
	actions := map[string]bool{}
	for k := range remediate.Specs {
		actions[k] = true
	}
	same("action.type", set(s.Defs.Action.Properties.Type.Enum), actions)
}

// El paquete de referencia de testdata/v1 usa toda la sintaxis del formato
// de reglas v1 (perfil propio que hereda del oficial, requires, referencias,
// all/any anidados, default, each, on_missing, acciones y safety). Los
// paquetes de los usuarios (rules.d) deben seguir cargando en toda la 1.x:
// si este test falla, el cambio en el código los rompe (ver docs/16).
func TestRulePackV1Reference(t *testing.T) {
	c := rule.NewCatalog()
	if err := c.LoadFS(rules.FS, "rules/"); err != nil {
		t.Fatalf("catálogo oficial: %v", err)
	}
	if err := c.LoadDir("testdata/v1/rules.d"); err != nil {
		t.Fatalf("paquete de referencia v1: %v", err)
	}
	for _, err := range c.Validate(probes.KnownSet(), remediate.ValidateAction) {
		t.Error(err)
	}
	r1, r2, r3 := c.Rule("EMP-LNX-001"), c.Rule("EMP-LNX-002"), c.Rule("EMP-WIN-001")
	if r1 == nil || r2 == nil || r3 == nil {
		t.Fatal("faltan reglas del paquete de referencia")
	}
	if len(r1.Requires) != 1 || r1.Requires[0] != "sudo-classic" || !r1.Check.HasDefault || r1.Check.Probe != "sysctl" ||
		r1.Check.Params["key"] != "net.ipv4.ip_forward" || len(r1.References.URLs) != 1 || r1.Impact == "" {
		t.Errorf("EMP-LNX-001 mal leída: %+v", r1)
	}
	if a := r1.Remediation.Actions; len(a) != 1 || a[0].Type != "sysctl.set" || a[0].Params["key"] != "net.ipv4.ip_forward" {
		t.Errorf("acciones de EMP-LNX-001: %+v", a)
	}
	if len(r2.Check.All) != 2 || len(r2.Check.All[1].Any) != 2 || r2.Check.All[0].Label != "montaje propio" {
		t.Errorf("EMP-LNX-002 (all/any anidados) mal leída: %+v", r2.Check)
	}
	if r3.Check.Each != "all" || r3.Check.OnMissing != "na" || r3.Remediation.Safety != "remote-access" || r3.Remediation.GPO == "" {
		t.Errorf("EMP-WIN-001 mal leída: %+v", r3)
	}
	if !c.Lineage("empresa-linux")["linux-server-l1"] {
		t.Error("el perfil propio debe heredar del oficial linux-server-l1")
	}
	if n := len(c.Select([]string{"linux-ubuntu", "linux-debian", "linux"}, "empresa-linux")); n <= 2 {
		t.Errorf("empresa-linux debe incluir sus reglas y las heredadas, tiene %d", n)
	}
}
