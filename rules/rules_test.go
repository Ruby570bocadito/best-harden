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
