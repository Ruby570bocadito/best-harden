package rule

import "testing"

// Las reglas de --rules-dir las escribe el usuario: el cargador y el lint no
// deben entrar en pánico con ningún YAML. Para buscar fallos:
//   go test -fuzz=FuzzLoadRule ./pkg/rule

func FuzzLoadRule(f *testing.F) {
	f.Add([]byte(base + "check:\n  probe: sysctl\n  key: net.ipv4.ip_forward\n  op: eq\n  expected: 0\n"))
	f.Add([]byte(base + "check:\n  any:\n    - probe: file\n      path: /etc/x\n      op: regex\n      expected: '(['\n    - probe: sysctl\n      key: k\n      op: between\n      expected: [1]\n"))
	f.Add([]byte(base + "requires: [sudo-classic]\nremediation:\n  summary: s\n  breaking_risk: none\n  actions:\n    - type: sysctl.set\n      key: k\n      value: 1\n---\nid: x\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c := NewCatalog()
		if err := c.loadFile(data, "fuzz.yaml", false); err != nil {
			return
		}
		c.Validate(map[string]bool{"sysctl": true, "file": true}, func(Action) error { return nil })
		for _, r := range c.Rules {
			r.MissingRequirement([]string{"linux"})
		}
	})
}
