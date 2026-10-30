package rules_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/internal/remediate"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
	"github.com/Ruby570bocadito/bastion/rules"
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
