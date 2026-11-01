// demo genera datos de demostración de Adarve sin leer ningún sistema: un
// servidor ficticio (web-01, Ubuntu 24.04) evaluado con el código real
// (reglas del catálogo, puntuación, superficie de ataque y firewall), para
// capturas de pantalla, documentación y pruebas de la interfaz que no deben
// mostrar datos de un equipo de verdad.
//
//	go run ./scripts/demo -out /tmp/demo          # informes HTML y JSON
//	go run ./scripts/demo -serve 127.0.0.1:8799   # la consola real con estos datos
//
// La consola de -serve es la de "adarve ui" (mismo servidor, misma CSP y el
// mismo token); solo cambia de dónde salen los datos. "Hacer la ronda" no
// escanea nada: devuelve la ronda de demostración.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/exceptions"
	"github.com/Ruby570bocadito/adarve/internal/platform"
	"github.com/Ruby570bocadito/adarve/internal/report"
	"github.com/Ruby570bocadito/adarve/internal/schedule"
	"github.com/Ruby570bocadito/adarve/internal/surface"
	"github.com/Ruby570bocadito/adarve/internal/ui"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
	"github.com/Ruby570bocadito/adarve/rules"
)

const (
	hostname = "web-01"
	version  = "0.5.0"
	profile  = "linux-server-l1"
)

// Brechas de la ronda actual: un servidor web razonable al que le faltan
// las cosas habituales.
var currentFails = []string{
	"LNX-FW-001", "LNX-MAC-001", "LNX-KRN-002", "LNX-KRN-005", "LNX-KRN-006",
	"LNX-NET-002", "LNX-NET-003", "LNX-NET-004", "LNX-SSH-001", "LNX-SSH-004",
	"LNX-SSH-006", "LNX-AUTH-003", "LNX-AUTH-006", "LNX-MOD-001", "LNX-FS-001",
	"LNX-LOG-001",
}

// Brechas que se fueron reparando en las rondas anteriores (de la más
// antigua a la más reciente, unas pocas por ronda).
var repairedOverTime = [][]string{
	{"LNX-SSH-010", "LNX-FS-006"},
	{"LNX-FS-007", "LNX-AUTH-005"},
	{"LNX-NET-007"},
	{"LNX-MOD-002", "LNX-MOD-003"},
	{"LNX-SSH-007"},
	{"LNX-AUTH-001"},
	{"LNX-KRN-001"},
}

// Excepción de demostración: un control aceptado por escrito.
var demoException = exceptions.Entry{
	Rule:   "LNX-SSH-012",
	Reason: "Bastión de salto gestionado por el equipo de red; el acceso SSH se filtra en el perímetro",
	Owner:  "equipo-infra",
}

func main() {
	out := flag.String("out", "", "carpeta donde escribir informe.html, puertas.html y sus JSON")
	serve := flag.String("serve", "", "servir la consola de demostración en esta dirección (p. ej. 127.0.0.1:8799)")
	flag.Parse()
	if *out == "" && *serve == "" {
		flag.Usage()
		os.Exit(2)
	}

	d, err := build(time.Now())
	if err != nil {
		log.Fatal(err)
	}
	if *out != "" {
		if err := d.write(*out); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("informes de demostración en %s\n", *out)
	}
	if *serve != "" {
		if err := d.serve(*serve); err != nil {
			log.Fatal(err)
		}
	}
}

// demo son todos los datos de la demostración.
type demo struct {
	host    platform.Info
	reports []*engine.Report // de la más antigua a la actual
	ids     []string
	surf    *surface.Report
	exc     []ui.Exception
}

func build(now time.Time) (*demo, error) {
	cat := rule.NewCatalog()
	if err := cat.LoadFS(rules.FS, "rules/"); err != nil {
		return nil, err
	}
	prof := cat.Profiles[profile]
	if prof == nil {
		return nil, fmt.Errorf("no existe el perfil %s", profile)
	}
	host := platform.Info{
		Hostname: hostname, OS: "linux", Family: "linux", Name: "Ubuntu 24.04.3 LTS",
		Distro: "ubuntu", Version: "24.04", Kernel: "6.8.0-79-generic", Arch: "amd64",
		Role: "server", IsAdmin: true,
		Tags: []string{"linux-ubuntu", "linux-debian", "linux", platform.TagSudoClassic},
	}
	for _, id := range append(append([]string{}, currentFails...), demoException.Rule) {
		if cat.Rule(id) == nil {
			return nil, fmt.Errorf("la demostración usa %s, que no está en el catálogo", id)
		}
	}
	selected := cat.Select(host.Tags, profile)
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID < selected[j].ID })

	d := &demo{host: host}
	rounds := len(repairedOverTime) + 1
	for i := 0; i < rounds; i++ {
		// En la ronda i siguen fallando las brechas actuales y las que se
		// repararon después de ella.
		fails := map[string]bool{}
		for _, id := range currentFails {
			fails[id] = true
		}
		for _, ids := range repairedOverTime[i:] {
			for _, id := range ids {
				fails[id] = true
			}
		}
		when := now.Add(-time.Duration(rounds-1-i) * 24 * time.Hour).Add(-3 * time.Minute)
		rep := evaluate(selected, host, prof, fails, when, i == rounds-1)
		if i > 0 {
			rep.Changes = engine.Diff(d.reports[i-1], rep)
		}
		d.reports = append(d.reports, rep)
		d.ids = append(d.ids, fmt.Sprintf("adarve-%s-%s", hostname, when.UTC().Format("20060102-150405")))
	}

	created := now.AddDate(0, 0, -40)
	expires := now.AddDate(0, 0, 50)
	d.exc = []ui.Exception{{
		Rule: demoException.Rule, Reason: demoException.Reason, Owner: demoException.Owner,
		Created: created.Format("2006-01-02"), Expires: expires.Format("2006-01-02"), DaysLeft: 50,
	}}

	surf, err := buildSurface(host, now)
	if err != nil {
		return nil, err
	}
	d.surf = surf
	return d, nil
}

// evaluate construye una ronda: las reglas de fails fallan, la de la
// excepción queda aceptada (solo en la ronda actual) y el resto se supera,
// salvo las que no aplican a este equipo.
func evaluate(selected []*rule.Rule, host platform.Info, prof *rule.Profile, fails map[string]bool, when time.Time, current bool) *engine.Report {
	var results []engine.Result
	for _, r := range selected {
		res := engine.Result{Rule: r, DurationMs: 3}
		switch {
		case r.MissingRequirement(host.Tags) != "":
			res.Status, res.Message = engine.NA, r.MissingRequirement(host.Tags)
		case r.Check.Op == "manual":
			// Lo que revisa una persona: la evidencia del equipo ficticio.
			res.Status, res.Actual, res.Expected = engine.Manual, demoEvidence[r.ID], "revisión manual"
			res.Probe, res.Source = r.Check.Probe, "demostración: equipo ficticio "+hostname
			if res.Actual == "" {
				res.Actual = "(ninguno)"
			}
		case current && r.ID == demoException.Rule:
			res.Status = engine.Exception
			res.Exception = &engine.ExceptionRef{Entry: demoException}
		case fails[r.ID] || r.ID == demoException.Rule:
			res.Status, res.Actual, res.Expected = engine.Fail, "no configurado", expected(r)
			res.Probe, res.Source = r.Check.Probe, "demostración: equipo ficticio "+hostname
		default:
			res.Status, res.Actual, res.Expected = engine.Pass, expected(r), expected(r)
			res.Probe, res.Source = r.Check.Probe, "demostración: equipo ficticio "+hostname
		}
		results = append(results, res)
	}
	return &engine.Report{
		Schema:     engine.SchemaVersion,
		Tool:       engine.ToolInfo{Name: "adarve", Version: version, Commit: "demo"},
		Host:       host,
		Profile:    prof,
		StartedAt:  when.Add(-2 * time.Second).UTC(),
		FinishedAt: when.UTC(),
		DurationMs: 1840,
		Score:      engine.ComputeScore(results),
		Results:    results,
	}
}

// demoEvidence es lo que encontraría en web-01 cada regla de revisión manual.
var demoEvidence = map[string]string{
	"LNX-AUTH-010": "/etc/group:27: sudo:x:27:ana,deploy, /etc/sudoers:50: %sudo ALL=(ALL:ALL) ALL, " +
		"/etc/sudoers.d/90-deploy:1: deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart web",
	"LNX-AUTH-011": "/etc/passwd:1: root:x:0:0:root:/root:/bin/bash, /etc/passwd:31: ana:x:1000:1000:Ana Ruiz:/home/ana:/bin/bash, " +
		"/etc/passwd:32: deploy:x:1001:1001:despliegues:/home/deploy:/bin/bash, /etc/passwd:33: backup-old:x:1002:1002::/home/backup-old:/bin/sh",
}

// expected resume el valor esperado de una regla para la evidencia.
func expected(r *rule.Rule) string {
	if v, ok := r.Check.Params["expected"]; ok {
		return fmt.Sprint(v)
	}
	return "conforme"
}

// Firewall de demostración (iptables-save): entrada bloqueada por defecto,
// SSH solo desde la red de gestión, la web abierta y dos puertas que nadie
// debería haber abierto (Redis y la API de Docker).
const iptablesSave = `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -s 192.168.10.0/24 -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 6379 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2375 -j ACCEPT
-A INPUT -s 10.20.0.0/16 -p tcp -m tcp --dport 9100 -j ACCEPT
COMMIT
`

func buildSurface(host platform.Info, now time.Time) (*surface.Report, error) {
	fw, err := surface.ParseLinuxFirewall(nil, iptablesSave, "")
	if err != nil {
		return nil, err
	}
	l := func(port int, addr, proc, user, path, pkg string, pid int) surface.Listener {
		sig := surface.SigPackage
		if pkg == "" {
			sig = surface.SigNoPackage
		}
		return surface.Listener{Proto: "tcp", Address: addr, Port: port, Scope: surface.ScopeOf(addr), PID: pid,
			Process: proc, User: user, Path: path, Signature: sig, Signer: pkg}
	}
	inv := surface.Inventory{
		Listeners: []surface.Listener{
			l(22, "0.0.0.0", "sshd", "root", "/usr/sbin/sshd", "openssh-server", 812),
			l(80, "0.0.0.0", "nginx", "root", "/usr/sbin/nginx", "nginx", 1034),
			l(443, "0.0.0.0", "nginx", "root", "/usr/sbin/nginx", "nginx", 1034),
			l(2375, "0.0.0.0", "dockerd", "root", "/usr/bin/dockerd", "docker-ce", 1201),
			l(3306, "0.0.0.0", "mysqld", "mysql", "/usr/sbin/mysqld", "mysql-server-8.0", 990),
			l(5432, "127.0.0.1", "postgres", "postgres", "/usr/lib/postgresql/16/bin/postgres", "postgresql-16", 1102),
			l(6379, "0.0.0.0", "redis-server", "redis", "/usr/bin/redis-server", "redis-server", 1150),
			l(9100, "0.0.0.0", "node_exporter", "prometheus", "/usr/local/bin/node_exporter", "", 1312),
		},
		Admins: []surface.Account{
			{Name: "root", Kind: "usuario", Source: "uid 0"},
			{Name: "ana", Kind: "usuario", Source: "grupo sudo"},
			{Name: "deploy", Kind: "usuario", Source: "grupo sudo"},
		},
		Shares:   []surface.Share{},
		Firewall: fw,
	}
	return surface.Analyze(inv, host, version, now), nil
}

// write deja los informes HTML y JSON en dir.
func (d *demo) write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cur := d.reports[len(d.reports)-1]
	var b bytes.Buffer
	if err := report.HTML(&b, cur); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "informe.html"), b.Bytes(), 0o644); err != nil {
		return err
	}
	b.Reset()
	if err := report.SurfaceHTML(&b, d.surf); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "puertas.html"), b.Bytes(), 0o644); err != nil {
		return err
	}
	for name, v := range map[string]any{"informe.json": cur, "puertas.json": d.surf} {
		j, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), j, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// serve sirve la consola real ("adarve ui") con los datos de demostración.
func (d *demo) serve(addr string) error {
	srv, err := ui.New(backend{d})
	if err != nil {
		return err
	}
	l, err := listen(addr)
	if err != nil {
		return err
	}
	fmt.Printf("consola de demostración: http://%s/?t=%s\n", l.Addr(), srv.Token())
	return srv.Serve(context.Background(), l)
}

// backend implementa ui.Backend con los datos de demostración.
type backend struct{ d *demo }

func (b backend) cur() *engine.Report { return b.d.reports[len(b.d.reports)-1] }

func (b backend) State() ui.State {
	return ui.State{Version: version, Hostname: hostname, System: b.d.host.Name, Family: "linux", Role: "server",
		Profile: b.cur().Profile.Name, ProfileID: profile, IsAdmin: true, ReportsDir: "/var/lib/adarve/reports"}
}

func (b backend) Scan(context.Context) (*engine.Report, string, error) {
	return b.cur(), b.d.ids[len(b.d.ids)-1], nil
}

func (b backend) Reports() ([]report.Meta, error) {
	var out []report.Meta
	for i, r := range b.d.reports {
		out = append(out, report.Meta{ID: b.d.ids[i], FinishedAt: r.FinishedAt, Hostname: hostname,
			Profile: profile, ProfileName: r.Profile.Name, Version: version, Score: r.Score})
	}
	return out, nil
}

func (b backend) Report(id string) (*engine.Report, error) {
	for i, x := range b.d.ids {
		if x == id {
			return b.d.reports[i], nil
		}
	}
	return nil, fmt.Errorf("no existe la ronda %s", id)
}

// Plan simula "adarve harden --wave N" sobre la ronda actual.
func (b backend) Plan(_ context.Context, wave int) ([]ui.PlanItem, error) {
	risks := map[string]int{"none": 1, "low": 1, "medium": 2, "high": 3}
	var items []ui.PlanItem
	for _, r := range b.cur().Results {
		if r.Status != engine.Fail {
			continue
		}
		rem := r.Rule.Remediation
		it := ui.PlanItem{RuleID: r.Rule.ID, Title: r.Rule.Title, Severity: string(r.Rule.Severity), Category: r.Rule.Category,
			Summary: rem.Summary, Risk: rem.BreakingRisk, Reboot: rem.RebootRequired}
		switch {
		case len(rem.Actions) == 0:
			it.Status = "manual"
		case rem.Safety == "remote-access":
			it.Status, it.Reason = "remote", "afecta al acceso remoto"
		case risks[rem.BreakingRisk] > wave:
			it.Status, it.Reason = "wave", fmt.Sprintf("riesgo de rotura %s: requiere --wave %d", rem.BreakingRisk, risks[rem.BreakingRisk])
		default:
			it.Status = "planned"
			for _, a := range rem.Actions {
				it.Steps = append(it.Steps, step(a))
			}
		}
		items = append(items, it)
	}
	return items, nil
}

// step describe una acción como lo haría el plan real.
func step(a rule.Action) string {
	p := func(k string) string { return fmt.Sprint(a.Params[k]) }
	switch a.Type {
	case "sysctl.set":
		return fmt.Sprintf("sysctl %s → %s", p("key"), p("value"))
	case "sshd.set":
		return fmt.Sprintf("sshd %s → %s", p("key"), p("value"))
	case "file.kv_set":
		return fmt.Sprintf("%s: %s → %s", p("path"), p("key"), p("value"))
	case "file.mode":
		return fmt.Sprintf("permisos %v → %s", a.Params["path"], p("mode"))
	case "kmod.block":
		return fmt.Sprintf("módulo %s: bloquear carga", p("name"))
	case "sudoers.defaults":
		return "sudoers: Defaults " + p("option")
	case "systemd.disable":
		return fmt.Sprintf("systemd %s: deshabilitar y detener", p("unit"))
	}
	return strings.ReplaceAll(a.Type, ".", " ")
}

func (b backend) Changes() ([]ui.Change, error) {
	when := b.cur().FinishedAt.AddDate(0, 0, -3)
	return []ui.Change{{ID: "chg-" + when.Format("20060102-150405"), CreatedAt: when, Wave: 1, Status: "applied",
		Profile: profile, Verified: 6}}, nil
}

func (b backend) Exceptions() ([]ui.Exception, error) { return b.d.exc, nil }

func (b backend) Surface(context.Context) (*surface.Report, error) { return b.d.surf, nil }

func (b backend) Schedule(context.Context) (*ui.ScheduleInfo, error) {
	info := &ui.ScheduleInfo{
		Status: schedule.Status{Enabled: true, Mechanism: "systemd (adarve-scan.timer)", At: "09:00", NextRun: "mañana 09:00"},
		Notify: "ntfy (https://ntfy.sh/…)",
	}
	for i, r := range b.d.reports {
		info.Runs = append(info.Runs, schedule.Run{Time: r.FinishedAt, ScanScore: r.Score.Value, SurfaceScore: 64 + i})
	}
	return info, nil
}

// listen abre addr, que debe ser una dirección de loopback: la consola de
// demostración no se expone a la red.
func listen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("%s no es una dirección de loopback (usa 127.0.0.1:puerto)", addr)
	}
	return net.Listen("tcp", addr)
}
