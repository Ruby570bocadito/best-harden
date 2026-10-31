package remediate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/probes"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// Sistema simulado: un almacén clave/valor que leen el probe y el remediador.
var (
	memMu  sync.Mutex
	memSys = map[string]string{}
)

func memGet(k string) (string, bool) {
	memMu.Lock()
	defer memMu.Unlock()
	v, ok := memSys[k]
	return v, ok
}
func memSet(k, v string) { memMu.Lock(); defer memMu.Unlock(); memSys[k] = v }
func memDel(k string)    { memMu.Lock(); defer memMu.Unlock(); delete(memSys, k) }

type memProbe struct{}

func (memProbe) Name() string         { return "memval" }
func (memProbe) DefaultField() string { return "value" }
func (memProbe) Collect(_ context.Context, p probes.Params) (probes.Observation, error) {
	v, ok := memGet(p.String("key"))
	if !ok {
		return probes.Observation{Found: false}, nil
	}
	return probes.Observation{Found: true, Fields: map[string]any{"value": v}}, nil
}

// memSetter escribe en el almacén. "broken" falla al aplicar; "noop" no hace nada.
type memSetter struct{}

func (memSetter) Type() string { return "mem.set" }
func (memSetter) Capture(_ context.Context, p probes.Params) (State, error) {
	if p.String("mode") == "skiplater" {
		memMu.Lock()
		captures[p.String("key")]++
		n := captures[p.String("key")]
		memMu.Unlock()
		if n > 1 {
			return skipState("ya no hay nada que cambiar"), nil
		}
	}
	v, ok := memGet(p.String("key"))
	return State{"exists": ok, "value": v}, nil
}
func (memSetter) Describe(p probes.Params, b State) string { return p.String("key") }
func (memSetter) Apply(_ context.Context, p probes.Params) error {
	switch p.String("mode") {
	case "broken":
		memSet(p.String("key"), "a-medias")
		return errors.New("fallo simulado")
	case "noop", "skiplater":
		return nil
	case "breakstore":
		// Tras aplicar, el almacén de instantáneas deja de poder escribirse.
		memSet(p.String("key"), p.String("value"))
		brokenStore.Dir = filepath.Join(brokenFile, "sub")
		return nil
	case "stuck":
		memSet(p.String("key"), "atascado")
		return nil
	}
	memSet(p.String("key"), p.String("value"))
	return nil
}
func (memSetter) Restore(_ context.Context, p probes.Params, b State) error {
	if p.String("mode") == "stuck" {
		return errors.New("restauración imposible")
	}
	if ok, _ := b["exists"].(bool); !ok {
		memDel(p.String("key"))
		return nil
	}
	memSet(p.String("key"), b["value"].(string))
	return nil
}

// Estado auxiliar de los modos especiales de memSetter.
var (
	captures    = map[string]int{}
	brokenStore *Store
	brokenFile  string
)

func init() {
	probes.Register(memProbe{})
	Register(memSetter{})
}

func memRule(id, key, want, risk, safety string, acts ...rule.Action) *rule.Rule {
	return &rule.Rule{ID: id, Title: id, Severity: rule.SevHigh, Category: "test",
		Check:       rule.Check{Probe: "memval", Op: "eq", Expected: want, Params: map[string]any{"key": key}},
		Remediation: rule.Remediation{Summary: "x", BreakingRisk: risk, Safety: safety, Actions: acts}}
}

func act(key, value, mode string) rule.Action {
	return rule.Action{Type: "mem.set", Params: map[string]any{"key": key, "value": value, "mode": mode}}
}

func newExecutor(t *testing.T) (*Executor, *Store) {
	st := &Store{Dir: t.TempDir()}
	verify := func(ctx context.Context, r *rule.Rule) engine.Result {
		return engine.New().Run(ctx, []*rule.Rule{r}, nil)[0]
	}
	return &Executor{Store: st, Verify: verify}, st
}

func TestHardenCycle(t *testing.T) {
	memSys = map[string]string{"a": "0", "c": "0", "d": "0"}
	rules := []*rule.Rule{
		memRule("T-A-001", "a", "1", "low", "", act("a", "1", "")),              // se aplica y verifica
		memRule("T-B-001", "b", "1", "low", "", act("b", "1", "")),              // no existía
		memRule("T-C-001", "c", "1", "low", "", act("c", "1", "broken")),        // falla al aplicar
		memRule("T-D-001", "d", "1", "low", "", act("d", "1", "noop")),          // no surte efecto
		memRule("T-E-001", "e", "1", "high", "", act("e", "1", "")),             // ola 3
		memRule("T-F-001", "f", "1", "low", "remote-access", act("f", "1", "")), // acceso remoto
		memRule("T-G-001", "g", "1", "low", ""),                                 // manual
	}
	ctx := context.Background()
	results := engine.New().Run(ctx, rules, nil)
	items := BuildPlan(ctx, results, Options{Wave: 1})

	status := map[string]ItemStatus{}
	for _, it := range items {
		status[it.Rule.ID] = it.Status
	}
	want := map[string]ItemStatus{"T-A-001": ItemPlanned, "T-B-001": ItemPlanned, "T-C-001": ItemPlanned,
		"T-D-001": ItemPlanned, "T-E-001": ItemWave, "T-F-001": ItemRemote, "T-G-001": ItemManual}
	for id, w := range want {
		if status[id] != w {
			t.Errorf("%s: estado %q, quiero %q", id, status[id], w)
		}
	}

	x, st := newExecutor(t)
	m, err := x.Execute(ctx, st.NewManifest("h", "p", "test", 1), items)
	if err != nil {
		t.Fatal(err)
	}
	outcome := map[string]string{}
	for _, it := range items {
		outcome[it.Rule.ID] = it.Outcome
	}
	if outcome["T-A-001"] != OutcomeVerified || outcome["T-B-001"] != OutcomeVerified {
		t.Errorf("A/B deberían verificarse: %v", outcome)
	}
	if outcome["T-C-001"] != OutcomeFailed || outcome["T-D-001"] != OutcomeNotEffective {
		t.Errorf("C debería fallar y D no surtir efecto: %v", outcome)
	}
	if v, _ := memGet("c"); v != "0" {
		t.Errorf("C debe quedar restaurado a 0 tras el fallo, es %q", v)
	}
	if m.Status != StatusPartial {
		t.Errorf("estado del cambio %q, quiero partial", m.Status)
	}
	if v, _ := memGet("a"); v != "1" {
		t.Fatalf("a = %q tras aplicar", v)
	}

	// Rollback desde el manifiesto guardado en disco (como haría otro proceso).
	loaded, err := st.Load(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := Rollback(ctx, loaded, nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := memGet("a"); v != "0" {
		t.Errorf("rollback: a = %q, quiero 0", v)
	}
	if _, ok := memGet("b"); ok {
		t.Error("rollback: b no existía y debe eliminarse")
	}
	if loaded.Status != StatusRolledBack {
		t.Errorf("estado tras rollback %q", loaded.Status)
	}
	if _, err := st.Latest(); err == nil {
		t.Error("no debería quedar nada que deshacer")
	}
}

func TestRemoteAccessNotConfirmed(t *testing.T) {
	memSys = map[string]string{"r": "0"}
	rules := []*rule.Rule{memRule("T-R-001", "r", "1", "low", "remote-access", act("r", "1", ""))}
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, rules, nil), Options{Wave: 1, IncludeRemote: true})
	x, st := newExecutor(t)
	armed := ""
	x.ArmDeadman = func(id string, _ time.Duration) error { armed = id; return nil }
	x.ConfirmRemote = func(time.Duration) bool { return false }
	x.DeadmanTimeout = 30 * time.Second
	m, err := x.Execute(ctx, st.NewManifest("h", "p", "test", 1), items)
	if err != nil {
		t.Fatal(err)
	}
	if armed != m.ID {
		t.Error("el dead-man switch debe armarse antes de aplicar")
	}
	if v, _ := memGet("r"); v != "0" {
		t.Errorf("sin confirmación el cambio debe revertirse, r = %q", v)
	}
	if items[0].Outcome != OutcomeReverted {
		t.Errorf("outcome %q", items[0].Outcome)
	}
}

func TestDeadmanRevertsUnconfirmed(t *testing.T) {
	memSys = map[string]string{"r": "0"}
	rules := []*rule.Rule{memRule("T-R-001", "r", "1", "low", "remote-access", act("r", "1", ""))}
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, rules, nil), Options{Wave: 1, IncludeRemote: true})
	x, st := newExecutor(t)
	// Simula que la sesión se corta: nadie confirma ni revierte en el proceso principal.
	x.ArmDeadman = func(string, time.Duration) error { return nil }
	// ConfirmRemote se llama con el cambio remoto ya aplicado y guardado.
	waiting := make(chan struct{})
	x.ConfirmRemote = func(time.Duration) bool { close(waiting); select {} }
	x.DeadmanTimeout = time.Second
	setMargin(t, 10*time.Millisecond)
	m := st.NewManifest("h", "p", "test", 1)
	go x.Execute(ctx, m, items) //nolint:errcheck // el proceso "muere" esperando
	<-waiting
	if err := RunDeadman(ctx, st, m.ID, time.Second); err != nil {
		t.Fatal(err)
	}
	if v, _ := memGet("r"); v != "0" {
		t.Errorf("el dead-man switch debe revertir, r = %q", v)
	}
	loaded, _ := st.Load(m.ID)
	if !loaded.DeadmanFired {
		t.Error("debe constar que saltó el dead-man switch")
	}
}

func TestGPOManagedSkipped(t *testing.T) {
	memSys = map[string]string{"k": "0"}
	r := memRule("T-P-001", "k", "1", "low", "",
		rule.Action{Type: "registry.set", Params: map[string]any{"path": `HKLM\SOFTWARE\Policies\X`, "name": "Y", "value": 1}})
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, []*rule.Rule{r}, nil), Options{Wave: 1, DomainJoined: true})
	if items[0].Status != ItemGPO {
		t.Errorf("estado %q, quiero gpo", items[0].Status)
	}
}

func TestValidateAction(t *testing.T) {
	ok := []rule.Action{
		{Type: "registry.set", Params: map[string]any{"path": `HKLM\SOFTWARE\X`, "name": "Y", "value": 1}},
		{Type: "secpol.set", Params: map[string]any{"section": "System Access", "key": "MinimumPasswordLength", "value": 14}},
		{Type: "auditpol.set", Params: map[string]any{"guid": "0CCE922B-69AE-11D9-BED3-505054503030", "success": true}},
		{Type: "defender.asr", Params: map[string]any{"guid": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "mode": "block"}},
		{Type: "sysctl.set", Params: map[string]any{"key": "net.ipv4.conf.all.rp_filter", "value": 1}},
		{Type: "sshd.set", Params: map[string]any{"key": "PermitRootLogin", "value": "no"}},
		{Type: "file.mode", Params: map[string]any{"path": "/etc/shadow", "mode": "0640", "group": []any{"shadow", "root"}}},
		{Type: "sudoers.defaults", Params: map[string]any{"option": "use_pty"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": `TCP Query User{AAB2B01C-3855-4816-88B1-0F4AB4DC07A0}C:\program files\ninjatrader 8\bin\ninjatrader.exe`, "remote": "LocalSubnet"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": "RemoteDesktop-UserMode-In-TCP", "remote": "LocalSubnet"}},
	}
	for _, a := range ok {
		if err := ValidateAction(a); err != nil {
			t.Errorf("%s debería ser válida: %v", a.Type, err)
		}
	}
	bad := []rule.Action{
		{Type: "exec", Params: map[string]any{"cmd": "rm -rf /"}},
		{Type: "registry.set", Params: map[string]any{"path": `HKCU\X`, "name": "Y", "value": 1}},
		{Type: "secpol.set", Params: map[string]any{"section": "System Access", "key": "NewAdministratorName", "value": 1}},
		{Type: "defender.asr", Params: map[string]any{"guid": "x; Remove-Item C:\\", "mode": "block"}},
		{Type: "defender.pref", Params: map[string]any{"name": "DisableRealtimeMonitoring", "value": 1}},
		{Type: "sshd.set", Params: map[string]any{"key": "PermitRootLogin", "value": "no\nPasswordAuthentication yes"}},
		{Type: "sshd.set", Params: map[string]any{"key": "Match", "value": "all"}},
		{Type: "sysctl.set", Params: map[string]any{"key": "../../etc/passwd", "value": 1}},
		{Type: "file.kv_set", Params: map[string]any{"path": "/root/.bashrc", "key": "X", "value": "y"}},
		{Type: "sudoers.defaults", Params: map[string]any{"option": "!authenticate"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": "RemoteDesktop-UserMode-In-TCP", "remote": "Any"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": "x\n'; Remove-Item C:\\", "remote": "LocalSubnet"}},
		{Type: "firewall.remote_address", Params: map[string]any{"rule": " ", "remote": "LocalSubnet"}},
	}
	for _, a := range bad {
		if err := ValidateAction(a); err == nil {
			t.Errorf("%s %v debería rechazarse", a.Type, a.Params)
		}
	}
}

func TestPlanRule(t *testing.T) {
	memSet("plan.k", "a")
	it := PlanRule(context.Background(), memRule("SURF-X", "plan.k", "b", "low", "", act("plan.k", "b", "")))
	if it.Status != ItemPlanned || len(it.Steps) != 1 || it.Steps[0].Before["value"] != "a" {
		t.Errorf("elemento: %+v", it)
	}
	it = PlanRule(context.Background(), memRule("SURF-Y", "plan.k", "b", "low", "", rule.Action{Type: "no.existe"}))
	if it.Status != ItemUnsupported {
		t.Errorf("acción desconocida: %+v", it)
	}
}

func setMargin(t *testing.T, d time.Duration) {
	t.Helper()
	old := DeadmanMargin
	DeadmanMargin = d
	t.Cleanup(func() { DeadmanMargin = old })
}

// El dead-man switch actúa mientras el usuario aún no ha confirmado; aunque
// después confirme, el cambio NO puede quedar como confirmado ni aplicado.
func TestDeadmanFiredBeforeConfirm(t *testing.T) {
	memSys = map[string]string{"r": "0"}
	rules := []*rule.Rule{memRule("T-R-001", "r", "1", "low", "remote-access", act("r", "1", ""))}
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, rules, nil), Options{Wave: 1, IncludeRemote: true})
	x, st := newExecutor(t)
	setMargin(t, 10*time.Millisecond)
	x.DeadmanTimeout = time.Second
	x.ArmDeadman = func(string, time.Duration) error { return nil }
	var id string
	x.ConfirmRemote = func(time.Duration) bool {
		// El usuario tarda: el dead-man switch (otro proceso) salta antes.
		if err := RunDeadman(ctx, st, id, time.Second); err != nil {
			t.Errorf("deadman: %v", err)
		}
		return true // ... y confirma tarde
	}
	m := st.NewManifest("h", "p", "test", 1)
	id = m.ID
	m, err := x.Execute(ctx, m, items)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := memGet("r"); v != "0" {
		t.Errorf("el cambio debe quedar revertido, r = %q", v)
	}
	if items[0].Outcome != OutcomeReverted {
		t.Errorf("outcome %q, quiero reverted", items[0].Outcome)
	}
	loaded, err := st.Load(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Confirmed || !loaded.DeadmanFired {
		t.Errorf("confirmed=%v deadman=%v: no se puede confirmar tras el dead-man switch", loaded.Confirmed, loaded.DeadmanFired)
	}
	if loaded.pending(nil) != 0 {
		t.Error("las entradas restauradas por el dead-man switch deben constar como deshechas")
	}
	if loaded.Status == StatusApplied {
		t.Errorf("estado %q", loaded.Status)
	}
}

func TestExecuteRejectsShortConfirmTimeout(t *testing.T) {
	memSys = map[string]string{"r": "0"}
	rules := []*rule.Rule{memRule("T-R-001", "r", "1", "low", "remote-access", act("r", "1", ""))}
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, rules, nil), Options{Wave: 1, IncludeRemote: true})
	x, st := newExecutor(t)
	x.ArmDeadman = func(string, time.Duration) error { return nil }
	x.ConfirmRemote = func(time.Duration) bool { return true }
	x.DeadmanTimeout = 10 * time.Second
	if _, err := x.Execute(ctx, st.NewManifest("h", "p", "test", 1), items); err == nil {
		t.Fatal("un plazo menor que el margen debe rechazarse")
	}
	if v, _ := memGet("r"); v != "0" {
		t.Error("no debe aplicarse nada")
	}
}

// Si la instantánea deja de poder guardarse a mitad de una regla, lo ya
// aplicado se deshace.
func TestSaveFailureRevertsAppliedSteps(t *testing.T) {
	memSys = map[string]string{"s1": "0", "s2": "0"}
	r := memRule("T-S-001", "s2", "1", "low", "", act("s1", "1", "breakstore"), act("s2", "1", ""))
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, []*rule.Rule{r}, nil), Options{Wave: 1})
	x, st := newExecutor(t)
	brokenStore = st
	brokenFile = filepath.Join(t.TempDir(), "fichero")
	if err := os.WriteFile(brokenFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := st.Dir
	t.Cleanup(func() { st.Dir = dir })
	x.Execute(ctx, st.NewManifest("h", "p", "test", 1), items) //nolint:errcheck // el guardado final también falla
	if v, _ := memGet("s1"); v != "0" {
		t.Errorf("s1 = %q: el paso aplicado debe revertirse al fallar el guardado", v)
	}
	if v, _ := memGet("s2"); v != "0" {
		t.Errorf("s2 = %q: no debe aplicarse sin instantánea", v)
	}
	if items[0].Outcome != OutcomeFailed {
		t.Errorf("outcome %q", items[0].Outcome)
	}
}

// Un fallo al revertir se comunica (no se dice "cambio revertido").
func TestRevertFailureIsReported(t *testing.T) {
	memSys = map[string]string{"k": "0"}
	r := memRule("T-K-001", "k", "1", "low", "", act("k", "1", "stuck"))
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, []*rule.Rule{r}, nil), Options{Wave: 1})
	x, st := newExecutor(t)
	m, err := x.Execute(ctx, st.NewManifest("h", "p", "test", 1), items)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Outcome != OutcomeNotEffective || !strings.Contains(items[0].Message, "NO se pudo revertir") {
		t.Errorf("mensaje: %q", items[0].Message)
	}
	if m.pending(nil) != 1 {
		t.Error("la entrada no restaurada debe seguir pendiente para adarve rollback")
	}
	b, _ := os.ReadFile(filepath.Join(st.Dir, "changes.log"))
	if !strings.Contains(string(b), "rollback-failed") {
		t.Errorf("changes.log debe registrar el fallo: %s", b)
	}
}

// Si al aplicar ya no queda nada que cambiar, el resultado es "nothing" y no
// cuenta como fallo.
func TestAllSkippedAtApplyIsNothing(t *testing.T) {
	memSys = map[string]string{"q": "0"}
	captures = map[string]int{}
	r := memRule("T-Q-001", "q", "1", "low", "", act("q", "1", "skiplater"))
	ctx := context.Background()
	items := BuildPlan(ctx, engine.New().Run(ctx, []*rule.Rule{r}, nil), Options{Wave: 1})
	x, st := newExecutor(t)
	m, err := x.Execute(ctx, st.NewManifest("h", "p", "test", 1), items)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].Outcome != OutcomeNothing || m.Status != StatusNothing {
		t.Errorf("outcome %q, estado %q", items[0].Outcome, m.Status)
	}
}

func TestPolicyManagedSecpolAuditpol(t *testing.T) {
	for _, typ := range []string{"secpol.set", "auditpol.set"} {
		if !managedByPolicy([]rule.Action{{Type: typ}}) {
			t.Errorf("%s debe considerarse gestionado por GPO en un equipo de dominio", typ)
		}
	}
	if managedByPolicy([]rule.Action{{Type: "registry.set", Params: map[string]any{"path": `HKLM\SYSTEM\X`}}}) {
		t.Error("una clave fuera de Policies no es de directiva")
	}
}

func TestLockStaleByPID(t *testing.T) {
	st := &Store{Dir: t.TempDir()}
	unlock, err := st.Lock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Lock(); err == nil {
		t.Error("el bloqueo de un proceso vivo no debe poder tomarse")
	}
	unlock()
	// Bloqueo de un proceso que ya no existe: se toma aunque sea reciente.
	if err := os.WriteFile(filepath.Join(st.Dir, ".lock"), []byte("2147483600 2026-01-01T00:00:00Z\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	unlock, err = st.Lock()
	if err != nil {
		t.Fatalf("un bloqueo abandonado debe recuperarse: %v", err)
	}
	unlock()
}

func TestSaveUsesUniqueTempFiles(t *testing.T) {
	st := &Store{Dir: t.TempDir()}
	m := st.NewManifest("h", "p", "test", 1)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Copias independientes, como dos procesos distintos.
			c := &Manifest{Schema: ManifestSchema, ID: m.ID, Status: StatusInProgress, store: st}
			for j := 0; j < 10; j++ {
				if err := c.Save(); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if _, err := st.Load(m.ID); err != nil {
		t.Fatal(err)
	}
	left, _ := filepath.Glob(filepath.Join(st.Dir, m.ID, "*.tmp"))
	if len(left) > 0 {
		t.Errorf("quedan temporales: %v", left)
	}
}

func TestValidateBefore(t *testing.T) {
	reg := rule.Action{Type: "registry.set", Params: map[string]any{"path": `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*`, "name": "NetbiosOptions", "value": 2}}
	sec := rule.Action{Type: "secpol.set", Params: map[string]any{"section": "System Access", "key": "MinimumPasswordLength", "value": 14}}
	fm := rule.Action{Type: "file.mode", Params: map[string]any{"path": "/etc/shadow", "mode": "0640"}}
	fw := rule.Action{Type: "firewall.remote_address", Params: map[string]any{"rule": "X", "remote": "LocalSubnet"}}
	sub := `SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{ABC}`
	ok := []struct {
		a rule.Action
		b State
	}{
		{reg, State{"values": []any{map[string]any{"sub": sub, "exists": true, "type": "DWORD", "value": "0"}}}},
		{reg, State{"values": []any{map[string]any{"sub": sub, "exists": false}}}},
		{sec, State{"exists": true, "value": "7"}},
		{fm, State{"path": "/etc/shadow", "mode": float64(0o640), "uid": float64(0), "gid": float64(42)}},
		{fw, State{"remote": "Any"}},
		{fw, State{"remote": "10.0.0.0/8,LocalSubnet"}},
	}
	for _, c := range ok {
		if err := ValidateBefore(c.a, c.b); err != nil {
			t.Errorf("%s %v debería ser válido: %v", c.a.Type, c.b, err)
		}
	}
	bad := []struct {
		a rule.Action
		b State
	}{
		// Otra clave HKLM distinta de la de la acción.
		{reg, State{"values": []any{map[string]any{"sub": `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "exists": true, "type": "SZ", "value": "evil.exe"}}}},
		{reg, State{"values": []any{map[string]any{"sub": sub, "exists": true, "type": "BINARY", "value": "00"}}}},
		{reg, State{"values": []any{map[string]any{"sub": sub, "exists": true, "type": "DWORD", "value": "99999999999"}}}},
		// Inyección en la plantilla de secedit.
		{sec, State{"exists": true, "value": "1\r\n[Privilege Rights]\r\nSeDebugPrivilege = *S-1-1-0"}},
		// chmod de un fichero que no es el de la acción.
		{fm, State{"path": "/etc/sudoers", "mode": float64(0o777)}},
		{fm, State{"path": "/etc/shadow", "mode": float64(0o100000)}},
		{fw, State{"remote": "Any; Remove-Item C:\\"}},
		{rule.Action{Type: "auditpol.set"}, State{"value": float64(9)}},
	}
	for _, c := range bad {
		if err := ValidateBefore(c.a, c.b); err == nil {
			t.Errorf("%s %v debería rechazarse", c.a.Type, c.b)
		}
	}
}

func TestValidateActionParams(t *testing.T) {
	bad := []rule.Action{
		{Type: "sysctl.set", Params: map[string]any{"key": "net.ipv6.conf.all.forwarding", "value": 0, "optinal": true}},
		{Type: "service.config", Params: map[string]any{"name": "Spooler", "start_type": "disabled", "stop": "ture"}},
		{Type: "registry.set", Params: map[string]any{"path": `HKLM\X`, "name": "Y", "value": 4294967296}},
		{Type: "registry.set", Params: map[string]any{"path": `HKLM\X`, "name": "Y", "value": -1}},
		{Type: "registry.set", Params: map[string]any{"path": `HKLM\X`, "name": "Y", "value": 1.5}},
		{Type: "secpol.set", Params: map[string]any{"section": "System Access", "key": "MinimumPasswordLength", "value": 14.5}},
	}
	for _, a := range bad {
		if err := ValidateAction(a); err == nil {
			t.Errorf("%s %v debería rechazarse", a.Type, a.Params)
		}
	}
	good := []rule.Action{
		{Type: "registry.set", Params: map[string]any{"path": `HKLM\X`, "name": "Y", "value": 4294967295}},
		{Type: "registry.set", Params: map[string]any{"path": `HKLM\X`, "name": "Y", "value": 4294967296, "value_type": "QWORD"}},
		{Type: "registry.set", Params: map[string]any{"path": `HKLM\X`, "name": "Y", "value": `%SystemRoot%\x`, "value_type": "EXPAND_SZ"}},
		{Type: "service.config", Params: map[string]any{"name": "Spooler", "start_type": "disabled", "stop": true}},
	}
	for _, a := range good {
		if err := ValidateAction(a); err != nil {
			t.Errorf("%s %v debería ser válida: %v", a.Type, a.Params, err)
		}
	}
	if rule.ActionOS == nil || rule.ActionOS("registry.set") != "windows" || rule.ActionOS("sysctl.set") != "linux" {
		t.Error("rule.ActionOS debe reflejar Spec.OS")
	}
}
