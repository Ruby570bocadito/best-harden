package rule

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const base = `
id: TST-LINT-001
title: Regla de prueba
description: d
category: c
severity: low
platforms: [linux]
profiles: [p]
remediation:
  summary: s
  breaking_risk: none
`

func lint(t *testing.T, extra string) []error {
	t.Helper()
	var r Rule
	if err := yaml.Unmarshal([]byte(base+extra), &r); err != nil {
		t.Fatal(err)
	}
	return r.Validate(map[string]bool{"sysctl": true, "file": true}, nil, nil)
}

func TestValidateCheckLint(t *testing.T) {
	if errs := lint(t, "check: {probe: sysctl, key: a.b, op: eq, expected: 1, on_missing: na}\n"); len(errs) != 0 {
		t.Fatalf("regla válida rechazada: %v", errs)
	}
	bad := map[string]string{
		"errata en clave común": "check: {probe: sysctl, key: a.b, op: eq, expected: 1, on_mising: na}\n",
		"regex inválida":        "check: {probe: sysctl, key: a.b, op: regex, expected: '('}\n",
		"between mal formado":   "check: {probe: sysctl, key: a.b, op: between, expected: 5}\n",
		"mode_max no octal":     "check: {probe: file, path: /x, op: mode_max, expected: '0999'}\n",
		"compuesta con op":      "check: {all: [{probe: sysctl, key: a.b, op: eq, expected: 1}], op: eq, expected: 1}\n",
	}
	for name, y := range bad {
		if errs := lint(t, y); len(errs) == 0 {
			t.Errorf("%s: debería rechazarse", name)
		}
	}
}

func TestValidateActionOS(t *testing.T) {
	old := ActionOS
	ActionOS = func(typ string) string {
		return map[string]string{"registry.set": "windows", "sysctl.set": "linux"}[typ]
	}
	defer func() { ActionOS = old }()
	errs := lint(t, "check: {probe: sysctl, key: a.b, op: eq, expected: 1}\n")
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var r Rule
	y := strings.Replace(base, "  breaking_risk: none\n", "  breaking_risk: none\n  actions:\n    - {type: registry.set, path: 'HKLM/X', name: Y, value: 1}\n", 1)
	if err := yaml.Unmarshal([]byte(y+"check: {probe: sysctl, key: a.b, op: eq, expected: 1}\n"), &r); err != nil {
		t.Fatal(err)
	}
	if errs := r.Validate(nil, nil, nil); len(errs) == 0 {
		t.Error("un registry.set en una regla de Linux debe rechazarse")
	}
}

func TestValidID(t *testing.T) {
	for _, id := range []string{"LNX-SSH-001", "ACME-WIN-NET-0001"} {
		if !ValidID(id) {
			t.Errorf("%s debería ser válido", id)
		}
	}
	for _, id := range []string{"lnx-ssh-001", "LNX-001", "LNX--001"} {
		if ValidID(id) {
			t.Errorf("%s debería ser inválido", id)
		}
	}
}
