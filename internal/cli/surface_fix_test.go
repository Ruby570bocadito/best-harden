package cli

import (
	"context"
	"sync"
	"testing"

	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/internal/remediate"
	"github.com/Ruby570bocadito/bastion/internal/surface"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// fakeFirewall simula las direcciones remotas de las reglas del Firewall de
// Windows con el mismo contrato que el remediador real.
type fakeFirewall struct {
	mu     sync.Mutex
	remote map[string]string
}

func (*fakeFirewall) Type() string { return "firewall.remote_address" }
func (f *fakeFirewall) Capture(_ context.Context, p probes.Params) (remediate.State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.remote[p.String("rule")]
	if v == p.String("remote") {
		return remediate.State{"skip": true, "reason": "ya limitada"}, nil
	}
	return remediate.State{"remote": v, "display": p.String("rule")}, nil
}
func (*fakeFirewall) Describe(p probes.Params, b remediate.State) string { return p.String("rule") }
func (f *fakeFirewall) Apply(_ context.Context, p probes.Params) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remote[p.String("rule")] = p.String("remote")
	return nil
}
func (f *fakeFirewall) Restore(_ context.Context, p probes.Params, b remediate.State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remote[p.String("rule")] = b["remote"].(string)
	return nil
}

func TestSurfaceFixRules(t *testing.T) {
	rep := &surface.Report{Findings: []surface.Finding{
		{ID: "SURF-PORT-3389", Title: "RDP accesible desde la red", Severity: rule.SevHigh,
			FirewallRules: []string{"RemoteDesktop-UserMode-In-TCP", "RemoteDesktop-UserMode-In-UDP"}},
		{ID: "SURF-APPS-OPEN", Title: "2 programas…", Severity: rule.SevLow, FirewallRules: []string{"{CFB7}", "TCP Query User{AAB2}C:\\x.exe"}},
		{ID: "SURF-NETBIOS", Title: "NetBIOS accesible solo desde la red local", Severity: rule.SevLow},
	}}
	rules, unknown := surfaceFixRules(rep, nil)
	if len(unknown) != 0 || len(rules) != 2 {
		t.Fatalf("reglas %d, desconocidos %v", len(rules), unknown)
	}
	rdp, apps := rules[0], rules[1]
	if rdp.Remediation.Safety != "remote-access" || len(rdp.Remediation.Actions) != 2 || apps.Remediation.Safety != "" {
		t.Errorf("RDP es acceso remoto y los programas no: %+v / %+v", rdp.Remediation, apps.Remediation)
	}
	for _, r := range rules {
		for _, a := range r.Remediation.Actions {
			if err := remediate.ValidateAction(a); err != nil {
				t.Errorf("%s: acción no válida: %v", r.ID, err)
			}
		}
	}
	if rules, unknown := surfaceFixRules(rep, []string{"surf-apps-open", "SURF-PORT-9999"}); len(rules) != 1 || rules[0].ID != "SURF-APPS-OPEN" ||
		len(unknown) != 1 || unknown[0] != "SURF-PORT-9999" {
		t.Errorf("filtro por ID: %v %v", rules, unknown)
	}
	// Un hallazgo sin reglas que limitar (NetBIOS ya limitado) no da error.
	if rules, unknown := surfaceFixRules(rep, []string{"SURF-NETBIOS"}); len(rules) != 0 || len(unknown) != 0 {
		t.Errorf("NetBIOS: %v %v", rules, unknown)
	}
}

// Una regla que abre puertos de dos hallazgos (hydra en el puerto de SSDP y
// en los suyos) se limita una sola vez, con el primero.
func TestSurfaceFixSharedRules(t *testing.T) {
	hydraUDP := "UDP Query User{4916}C:\\hydra-python-rpc.exe"
	rep := &surface.Report{Findings: []surface.Finding{
		{ID: "SURF-PORT-1900", Severity: rule.SevMedium, FirewallRules: []string{hydraUDP}},
		{ID: "SURF-SUNSHINE", Severity: rule.SevMedium, FirewallRules: []string{"{SUNSHINE}"}},
		{ID: "SURF-APPS-OPEN", Severity: rule.SevLow, FirewallRules: []string{"TCP Query User{45D8}C:\\hydra-python-rpc.exe", hydraUDP}},
		{ID: "SURF-FOO", Severity: rule.SevLow, FirewallRules: []string{hydraUDP}},
	}}
	rules, _ := surfaceFixRules(rep, nil)
	if len(rules) != 4 {
		t.Fatalf("reglas: %d", len(rules))
	}
	if n := len(rules[2].Remediation.Actions); n != 1 || rules[2].Remediation.Actions[0].Params["rule"] != "TCP Query User{45D8}C:\\hydra-python-rpc.exe" {
		t.Errorf("SURF-APPS-OPEN solo limita la regla TCP: %+v", rules[2].Remediation.Actions)
	}
	if len(rules[3].Remediation.Actions) != 0 || rules[3].Remediation.Summary != "sus reglas ya se limitan con SURF-PORT-1900" {
		t.Errorf("sin reglas propias: %+v", rules[3].Remediation)
	}
	if rules[1].Remediation.Safety != "remote-access" {
		t.Error("Sunshine es acceso remoto: requiere --include-remote")
	}
	// Pedido solo SURF-APPS-OPEN, se queda con las dos reglas.
	if rules, _ := surfaceFixRules(rep, []string{"SURF-APPS-OPEN"}); len(rules) != 1 || len(rules[0].Remediation.Actions) != 2 {
		t.Errorf("solo programas: %+v", rules)
	}
}

func TestSurfaceFixCycle(t *testing.T) {
	fw := &fakeFirewall{remote: map[string]string{"{CFB7}": "Any", "TCP Query User{AAB2}C:\\x.exe": "Any"}}
	remediate.Register(fw)
	rep := &surface.Report{Findings: []surface.Finding{
		{ID: "SURF-APPS-OPEN", Title: "2 programas…", Severity: rule.SevLow, FirewallRules: []string{"{CFB7}", "TCP Query User{AAB2}C:\\x.exe"}},
	}}
	rules, _ := surfaceFixRules(rep, nil)
	items := []*remediate.Item{remediate.PlanRule(context.Background(), rules[0])}
	if items[0].Status != remediate.ItemPlanned || len(items[0].Steps) != 2 {
		t.Fatalf("plan: %+v", items[0])
	}
	store := &remediate.Store{Dir: t.TempDir()}
	x := &remediate.Executor{Store: store, Verify: verifyFirewallSteps(items)}
	m, err := x.Execute(context.Background(), store.NewManifest("pc-01", "surface", "test", 0), items)
	if err != nil || m.Status != remediate.StatusApplied || items[0].Outcome != remediate.OutcomeVerified {
		t.Fatalf("aplicar: %v %s %s %s", err, m.Status, items[0].Outcome, items[0].Message)
	}
	if fw.remote["{CFB7}"] != "LocalSubnet" || fw.remote["TCP Query User{AAB2}C:\\x.exe"] != "LocalSubnet" {
		t.Errorf("tras aplicar: %v", fw.remote)
	}
	// La instantánea se lee de disco y se deshace como un harden.
	loaded, err := store.Load(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := remediate.Rollback(context.Background(), loaded, nil); err != nil || loaded.Status != remediate.StatusRolledBack {
		t.Fatalf("rollback: %v %s", err, loaded.Status)
	}
	if fw.remote["{CFB7}"] != "Any" || fw.remote["TCP Query User{AAB2}C:\\x.exe"] != "Any" {
		t.Errorf("tras deshacer: %v", fw.remote)
	}
	// Si la regla no queda limitada, la verificación falla y se revierte.
	broken := &stuckFirewall{fakeFirewall: fw}
	remediate.Register(broken)
	items = []*remediate.Item{remediate.PlanRule(context.Background(), rules[0])}
	_, _ = x.Execute(context.Background(), store.NewManifest("pc-01", "surface", "test", 0), items)
	if items[0].Outcome != remediate.OutcomeNotEffective || fw.remote["{CFB7}"] != "Any" {
		t.Errorf("sin efecto: %s %v", items[0].Outcome, fw.remote)
	}
}

// stuckFirewall acepta el cambio pero no lo aplica.
type stuckFirewall struct{ *fakeFirewall }

func (*stuckFirewall) Apply(context.Context, probes.Params) error { return nil }
