package exceptions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func day(s string) time.Time {
	t, err := time.ParseInLocation(DateLayout, s, time.Local)
	if err != nil {
		panic(err)
	}
	return t
}

func entry(rule, created, expires string, hosts ...string) Entry {
	return Entry{Rule: rule, Reason: "equipo sin UEFI, se sustituye en enero", Owner: "seguridad", Created: created, Expires: expires, Hosts: hosts}
}

func TestValidate(t *testing.T) {
	now := day("2026-10-15").Add(10 * time.Hour)
	ok := entry("WIN-SYS-003", "2026-10-15", "2027-01-31")
	if err := ok.ValidateAt(now); err != nil {
		t.Fatalf("excepción válida rechazada: %v", err)
	}
	bad := map[string]Entry{
		"id":           {Rule: "rm -rf", Reason: ok.Reason, Created: ok.Created, Expires: ok.Expires},
		"motivo corto": {Rule: ok.Rule, Reason: "porque sí", Created: ok.Created, Expires: ok.Expires},
		"salto línea":  {Rule: ok.Rule, Reason: "motivo largo\nsegunda línea", Created: ok.Created, Expires: ok.Expires},
		"sin fecha":    {Rule: ok.Rule, Reason: ok.Reason, Created: ok.Created},
		"más de 1 año": entry("WIN-SYS-003", "2026-10-15", "2027-12-31"),
		"al revés":     entry("WIN-SYS-003", "2026-10-15", "2026-10-01"),
		// Creación futura: sería vigente desde hoy durante más de un año.
		"creada en el futuro":    entry("WIN-SYS-003", "2030-01-01", "2030-12-31"),
		"más de 1 año desde hoy": entry("WIN-SYS-003", "2026-10-16", "2027-10-20"),
	}
	for name, e := range bad {
		if err := e.ValidateAt(now); err == nil {
			t.Errorf("%s: debería ser inválida", name)
		}
	}
	// IDs con el formato de las reglas (incluidas las de terceros).
	for _, id := range []string{"ACME-LNX-SSH-001", "LNX-SSH-1001", "WIN-DC-001"} {
		e := entry(id, "2026-10-15", "2027-01-31")
		if err := e.ValidateAt(now); err != nil {
			t.Errorf("%s debería admitirse: %v", id, err)
		}
	}
}

func TestExpiry(t *testing.T) {
	e := entry("WIN-SYS-003", "2026-10-15", "2026-10-31")
	if e.Expired(day("2026-10-31").Add(23 * time.Hour)) {
		t.Error("el día de caducidad todavía es vigente")
	}
	if !e.Expired(day("2026-11-01")) {
		t.Error("al día siguiente debe estar caducada")
	}
	if d := e.DaysLeft(day("2026-10-30")); d != 2 {
		t.Errorf("días restantes = %d, quiero 2", d)
	}
}

func TestFind(t *testing.T) {
	f := &File{Exceptions: []Entry{
		entry("WIN-SYS-003", "2026-01-01", "2026-06-30"),
		entry("WIN-SYS-003", "2026-09-01", "2027-03-31", "PC-01"),
		entry("LNX-FW-001", "2026-01-01", "2026-03-31"),
	}}
	now := day("2026-10-15")
	if e, expired := f.Find("WIN-SYS-003", "pc-01", now); e == nil || expired || e.Expires != "2027-03-31" {
		t.Errorf("PC-01 debería tener la excepción vigente: %+v %v", e, expired)
	}
	if e, expired := f.Find("WIN-SYS-003", "PC-02", now); e == nil || !expired {
		t.Errorf("PC-02 solo tiene la caducada: %+v %v", e, expired)
	}
	if e, _ := f.Find("WIN-NET-006", "PC-01", now); e != nil {
		t.Errorf("sin excepción: %+v", e)
	}
}

func TestUpsertRemove(t *testing.T) {
	f := &File{}
	if f.Upsert(entry("WIN-SYS-003", "2026-10-15", "2027-01-31")) {
		t.Error("la primera no sustituye")
	}
	if !f.Upsert(entry("WIN-SYS-003", "2026-10-15", "2027-02-28")) {
		t.Error("misma regla y equipos: sustituye")
	}
	f.Upsert(entry("WIN-SYS-003", "2026-10-15", "2027-02-28", "PC-01"))
	if len(f.Exceptions) != 2 {
		t.Fatalf("quiero 2 excepciones, hay %d", len(f.Exceptions))
	}
	if n := f.Remove("win-sys-003", "pc-01"); n != 1 || len(f.Exceptions) != 1 {
		t.Errorf("eliminar la de PC-01: %d, quedan %d", n, len(f.Exceptions))
	}
	if n := f.Remove("WIN-SYS-003", ""); n != 1 || len(f.Exceptions) != 0 {
		t.Errorf("eliminar todas: %d, quedan %d", n, len(f.Exceptions))
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exceptions.yaml")
	if f, err := Load(path); err != nil || len(f.Exceptions) != 0 {
		t.Fatalf("sin fichero: %v %v", f, err)
	}
	f := &File{}
	f.Upsert(entry("WIN-SYS-003", "2026-10-15", "2027-01-31", "PC-01"))
	f.Upsert(entry("LNX-FW-001", "2026-10-15", "2026-12-31"))
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	g, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Exceptions) != 2 || g.Exceptions[0].Rule != "LNX-FW-001" || g.Exceptions[1].Hosts[0] != "PC-01" {
		t.Errorf("ida y vuelta: %+v", g.Exceptions)
	}

	// Una excepción inválida editada a mano se ignora (y se avisa); el resto sigue.
	b, _ := os.ReadFile(path)
	b = []byte(strings.Replace(string(b), "2026-12-31", "2028-12-31", 1))
	os.WriteFile(path, b, 0o640)
	g, err = Load(path)
	if err == nil || len(g.Exceptions) != 1 {
		t.Errorf("la inválida debe ignorarse con aviso: %v %+v", err, g.Exceptions)
	}

	// Un fichero guardado por Bastion (el nombre anterior) sigue valiendo.
	b, _ = os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), Schema, legacySchema, 1)), 0o640)
	if g, err = Load(path); g.Schema != Schema || len(g.Exceptions) != 1 {
		t.Errorf("formato de Bastion: %v %+v", err, g)
	}
}

func TestParseExpiry(t *testing.T) {
	now := day("2026-10-15").Add(15 * time.Hour)
	cases := map[string]string{"2027-03-31": "2027-03-31", "90d": "2027-01-13", "2w": "2026-10-29", "6m": "2027-04-15", "1y": "2027-10-15"}
	for in, want := range cases {
		got, err := ParseExpiry(in, now)
		if err != nil || got.Format(DateLayout) != want {
			t.Errorf("%s → %s %v, quiero %s", in, got.Format(DateLayout), err, want)
		}
	}
	for _, in := range []string{"", "mañana", "0d", "-5d", "10x"} {
		if _, err := ParseExpiry(in, now); err == nil {
			t.Errorf("%q debería ser inválido", in)
		}
	}
}
