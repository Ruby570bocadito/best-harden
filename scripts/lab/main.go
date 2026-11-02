// lab compara los informes del laboratorio de CI con su resultado esperado
// (golden files): un fichero por imagen en scripts/lab/esperado con el
// estado de cada control en un runner de GitHub sin tocar. Un cambio en una
// regla o en un probe que convierte un control conforme en una brecha (un
// falso positivo) aparece en el PR; un cambio de la imagen, en la ejecución
// semanal. Ver docs/11-desarrollo.md#laboratorio.
//
//	lab check -golden scripts/lab/esperado/ubuntu-24.04.txt antes-*.json
//	lab cycle -golden scripts/lab/esperado/ubuntu-24.04.txt -before antes.json \
//	    -after despues.json -restored restaurado.json -manifest manifest.json
//
// check falla si un control no tiene el estado esperado, si un control no
// tiene resultado esperado o ya no se evalúa, o si alguno da error o queda
// sin evaluar: en una imagen limpia y con privilegios, eso es un fallo del
// probe. Con -propose escribe el fichero esperado que sale de los informes,
// para revisarlo y copiarlo al repositorio.
//
// cycle comprueba el ciclo harden → rollback control a control: lo que
// harden da por reparado pasa en el escaneo siguiente, nada de lo que pasaba
// deja de pasar y el rollback deja cada control como estaba.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/remediate"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "check":
		err = runCheck(os.Args[2:], os.Stdout)
	case "cycle":
		err = runCycle(os.Args[2:], os.Stdout)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lab:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "uso: lab check -golden FICHERO [-propose FICHERO] INFORME.json...\n"+
		"     lab cycle -golden FICHERO -before A.json -after B.json -restored C.json -manifest M.json")
	os.Exit(2)
}

// Estados que puede esperar un fichero. Un error o un control sin evaluar
// no se aceptan nunca: se corrige el probe o la regla.
var allowed = map[engine.Status]bool{engine.Pass: true, engine.Fail: true, engine.NA: true, engine.Manual: true}

// reviewMark señala en una propuesta las líneas que hay que revisar; un
// fichero esperado no puede conservarla.
const reviewMark = "# REVISAR"

// expectation es una línea del fichero esperado.
type expectation struct {
	statuses []engine.Status // más de uno: el control cambia con el tiempo
	line     string          // tal cual, para conservar la evidencia y el motivo
}

type golden struct {
	image string // la imagen con la que se revisó (línea «# Imagen:»)
	byID  map[string]expectation
}

func parseGolden(r io.Reader) (*golden, error) {
	g := &golden{byID: map[string]expectation{}}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), " \t\r")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			if v, ok := strings.CutPrefix(t, "# Imagen:"); ok && g.image == "" {
				g.image = strings.TrimSpace(v)
			}
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 {
			return nil, fmt.Errorf("línea %d: falta el estado de %s", n, f[0])
		}
		id := f[0]
		if _, dup := g.byID[id]; dup {
			return nil, fmt.Errorf("línea %d: %s está repetido", n, id)
		}
		if strings.Contains(line, reviewMark) {
			return nil, fmt.Errorf("línea %d: %s sigue marcado para revisar; quita la marca cuando lo hayas revisado", n, id)
		}
		var sts []engine.Status
		for _, s := range strings.Split(f[1], "|") {
			st := engine.Status(s)
			if !allowed[st] {
				return nil, fmt.Errorf("línea %d: %s no puede esperar %q (solo pass, fail, na o manual: un error o un control sin evaluar se corrigen, no se aceptan)", n, id, s)
			}
			sts = append(sts, st)
		}
		if len(sts) > 1 && !strings.Contains(line, "# ") {
			return nil, fmt.Errorf("línea %d: %s admite varios estados y no dice por qué (añade «# motivo»)", n, id)
		}
		g.byID[id] = expectation{statuses: sts, line: line}
	}
	return g, sc.Err()
}

// loadGolden lee el fichero esperado; si aún no existe devuelve nil.
func loadGolden(path string) (*golden, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	g, err := parseGolden(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return g, nil
}

// volatile son los controles que admiten más de un estado.
func (g *golden) volatile() map[string]bool {
	v := map[string]bool{}
	if g != nil {
		for id, e := range g.byID {
			if len(e.statuses) > 1 {
				v[id] = true
			}
		}
	}
	return v
}

// observed es el resultado de un control en el laboratorio.
type observed struct {
	status engine.Status
	detail string
}

type observation struct {
	byID     map[string]observed
	host     string
	profiles []string
}

func readReport(path string) (*engine.Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rep engine.Report
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if rep.Schema != engine.SchemaVersion {
		return nil, fmt.Errorf("%s: esquema %q, se esperaba %q", path, rep.Schema, engine.SchemaVersion)
	}
	return &rep, nil
}

// readReports junta los informes de varios perfiles. El estado de un
// control no depende del perfil: si dos informes discrepan, es un problema.
func readReports(paths []string) (*observation, []string, error) {
	o := &observation{byID: map[string]observed{}}
	var problems []string
	for _, p := range paths {
		rep, err := readReport(p)
		if err != nil {
			return nil, nil, err
		}
		if o.host == "" {
			o.host = strings.TrimSpace(rep.Host.Name + " · " + rep.Host.Kernel)
		}
		if rep.Profile != nil {
			o.profiles = append(o.profiles, rep.Profile.ID)
		}
		for _, r := range rep.Results {
			cur := observed{status: r.Status, detail: detail(r.Eval)}
			if prev, ok := o.byID[r.Rule.ID]; ok {
				if prev.status != cur.status {
					problems = append(problems, fmt.Sprintf("%-14s %s en un perfil y %s en otro: el estado no puede depender del perfil", r.Rule.ID, prev.status, cur.status))
				}
				continue
			}
			o.byID[r.Rule.ID] = cur
		}
	}
	return o, problems, nil
}

// detail resume la evidencia: para un fallo, el primer valor que no cumple y
// de dónde sale; para un error, un control sin evaluar o uno que no aplica,
// el motivo. Lo primero es el valor: si no cabe, se corta el origen.
func detail(e engine.Eval) string {
	var s string
	switch e.Status {
	case engine.Fail:
		if l := failingLeaf(e); l != nil {
			parts := []string{fmt.Sprintf("actual «%s» · esperado «%s»", l.Actual, l.Expected)}
			for _, p := range []string{l.Label, l.Source} {
				if p != "" {
					parts = append(parts, p)
				}
			}
			if len(parts) == 1 && firstNonEmpty(l.Field, l.Probe) != "" {
				parts = append(parts, firstNonEmpty(l.Field, l.Probe))
			}
			s = strings.Join(parts, " · ")
		}
	case engine.Error, engine.Skipped, engine.NA:
		s = firstMessage(e)
	}
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 140 {
		s = string(r[:139]) + "…"
	}
	return s
}

func failingLeaf(e engine.Eval) *engine.Eval {
	if len(e.Children) == 0 {
		if e.Status == engine.Fail {
			return &e
		}
		return nil
	}
	for _, c := range e.Children {
		if l := failingLeaf(c); l != nil {
			return l
		}
	}
	return nil
}

func firstMessage(e engine.Eval) string {
	if e.Message != "" {
		return e.Message
	}
	for _, c := range e.Children {
		if m := firstMessage(c); m != "" {
			return m
		}
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// compare devuelve las diferencias entre lo observado y lo esperado.
func compare(g *golden, o *observation) []string {
	var problems []string
	for _, id := range sortedKeys(o.byID) {
		got := o.byID[id]
		if got.status == engine.Error || got.status == engine.Skipped {
			problems = append(problems, fmt.Sprintf("%-14s %s en una imagen limpia: %s", id, got.status, firstNonEmpty(got.detail, "sin mensaje")))
			continue
		}
		want, ok := g.byID[id]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%-14s no tiene resultado esperado (obtenido %s)%s", id, got.status, suffix(got.detail)))
		case !slices.Contains(want.statuses, got.status):
			problems = append(problems, fmt.Sprintf("%-14s esperado %s, obtenido %s%s", id, joinStatus(want.statuses), got.status, suffix(got.detail)))
		}
	}
	for _, id := range sortedKeys(g.byID) {
		if _, ok := o.byID[id]; !ok {
			problems = append(problems, fmt.Sprintf("%-14s ya no se evalúa (esperado %s)", id, joinStatus(g.byID[id].statuses)))
		}
	}
	return problems
}

// propose escribe el fichero esperado que sale de lo observado. Conserva tal
// cual las líneas que siguen valiendo (con su evidencia revisada y su
// motivo) y marca para revisar las demás.
func propose(name, image string, g *golden, o *observation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Laboratorio de Adarve · %s\n", name)
	fmt.Fprintf(&b, "# Imagen: %s\n", firstNonEmpty(image, "desconocida"))
	fmt.Fprintf(&b, "# Sistema: %s\n", o.host)
	fmt.Fprintf(&b, "# Perfiles: %s\n", strings.Join(o.profiles, ", "))
	b.WriteString(`#
# Estado esperado de cada control en la imagen del runner de GitHub, sin
# tocar. Cada «fail» está revisado con su evidencia: es una brecha real de
# la imagen, no un falso positivo. Solo se compara el estado; lo que sigue
# es la evidencia de la revisión. Un control con varios estados (pass|fail)
# cambia con el tiempo y lleva su motivo tras «#».
# Cómo revisar y aceptar cambios: docs/11-desarrollo.md#laboratorio

`)
	ids := sortedKeys(o.byID)
	w := 0
	for _, id := range ids {
		w = max(w, len(id))
	}
	for _, id := range ids {
		got := o.byID[id]
		var want expectation
		known := false
		if g != nil {
			want, known = g.byID[id]
		}
		if known && slices.Contains(want.statuses, got.status) {
			b.WriteString(want.line + "\n")
			continue
		}
		line := fmt.Sprintf("%-*s  %-6s", w, id, got.status)
		if got.detail != "" {
			line += "  " + got.detail
		}
		line = strings.TrimRight(line, " ")
		switch {
		case got.status == engine.Error || got.status == engine.Skipped:
			line += "  " + reviewMark + ": corrige el probe o la regla"
		case known:
			line += "  " + reviewMark + ": antes " + joinStatus(want.statuses)
		case g != nil:
			line += "  " + reviewMark + ": control nuevo"
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func runCheck(args []string, out io.Writer) error {
	fl := flag.NewFlagSet("check", flag.ExitOnError)
	goldenPath := fl.String("golden", "", "fichero esperado (scripts/lab/esperado/<imagen>.txt)")
	proposePath := fl.String("propose", "", "escribir aquí el fichero esperado que sale de los informes")
	_ = fl.Parse(args)
	if *goldenPath == "" || fl.NArg() == 0 {
		usage()
	}
	name := strings.TrimSuffix(filepath.Base(*goldenPath), filepath.Ext(*goldenPath))
	image := strings.TrimSpace(os.Getenv("ImageOS") + " " + os.Getenv("ImageVersion"))

	g, err := loadGolden(*goldenPath)
	if err != nil {
		return err
	}
	o, problems, err := readReports(fl.Args())
	if err != nil {
		return err
	}
	if g == nil {
		problems = append(problems, fmt.Sprintf("no hay fichero esperado para %s: revisa la propuesta y guárdala en %s", name, *goldenPath))
	} else {
		problems = append(problems, compare(g, o)...)
	}
	proposal := propose(name, image, g, o)
	if *proposePath != "" {
		if err := os.WriteFile(*proposePath, []byte(proposal), 0o644); err != nil {
			return err
		}
	}
	if len(problems) == 0 {
		fmt.Fprintf(out, "Laboratorio %s: los %d controles tienen el estado esperado (imagen %s).\n", name, len(o.byID), firstNonEmpty(image, "desconocida"))
		return nil
	}
	fmt.Fprintf(out, "Laboratorio %s: %d %s con %s\n", name, len(problems), plural(len(problems), "diferencia", "diferencias"), *goldenPath)
	if g != nil && g.image != "" && image != "" && g.image != image {
		fmt.Fprintf(out, "La imagen ha cambiado desde la revisión: %s → %s.\n", g.image, image)
	}
	for _, p := range problems {
		fmt.Fprintln(out, "  "+p)
	}
	fmt.Fprintf(out, "\nSi el cambio es correcto, revisa cada «fail» con su evidencia y copia la propuesta en %s\n", *goldenPath)
	fmt.Fprintf(out, "(docs/11-desarrollo.md#laboratorio):\n-----8<-----\n%s-----8<-----\n", proposal)
	summary(name, problems, proposal)
	return fmt.Errorf("%s: el laboratorio no coincide con el resultado esperado", name)
}

// summary deja las diferencias y la propuesta en el resumen del job de
// GitHub Actions, que se lee sin abrir el registro.
func summary(name string, problems []string, proposal string) {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "### Laboratorio %s: %d %s\n\n```text\n%s\n```\n\nPropuesta de fichero esperado:\n\n```text\n%s```\n",
		name, len(problems), plural(len(problems), "diferencia", "diferencias"), strings.Join(problems, "\n"), proposal)
}

func runCycle(args []string, out io.Writer) error {
	fl := flag.NewFlagSet("cycle", flag.ExitOnError)
	goldenPath := fl.String("golden", "", "fichero esperado (para saber qué controles cambian con el tiempo)")
	beforeP := fl.String("before", "", "informe antes de harden")
	afterP := fl.String("after", "", "informe después de harden")
	restoredP := fl.String("restored", "", "informe después del rollback")
	manifestP := fl.String("manifest", "", "manifiesto del cambio (adarve.change/v1), leído tras el rollback")
	_ = fl.Parse(args)
	if *beforeP == "" || *afterP == "" || *restoredP == "" || *manifestP == "" {
		usage()
	}
	g, err := loadGolden(*goldenPath)
	if err != nil {
		return err
	}
	var obs [3]*observation
	for i, p := range []string{*beforeP, *afterP, *restoredP} {
		o, problems, err := readReports([]string{p})
		if err != nil {
			return err
		}
		if len(problems) > 0 {
			return fmt.Errorf("%s: %s", p, strings.Join(problems, "; "))
		}
		obs[i] = o
	}
	b, err := os.ReadFile(*manifestP)
	if err != nil {
		return err
	}
	var m remediate.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("%s: %w", *manifestP, err)
	}
	problems, verified := cycleProblems(g.volatile(), obs[0], obs[1], obs[2], &m)
	if len(problems) == 0 {
		fmt.Fprintf(out, "Ciclo harden → rollback: %d %s y verificados; nada roto y el rollback deja los %d controles como estaban.\n",
			verified, plural(verified, "control reparado", "controles reparados"), len(obs[0].byID))
		return nil
	}
	fmt.Fprintf(out, "Ciclo harden → rollback: %d %s\n", len(problems), plural(len(problems), "problema", "problemas"))
	for _, p := range problems {
		fmt.Fprintln(out, "  "+p)
	}
	return errors.New("el ciclo harden → rollback no es limpio")
}

func cycleProblems(vol map[string]bool, before, after, restored *observation, m *remediate.Manifest) ([]string, int) {
	var problems []string
	verified := 0
	for _, r := range m.Rules {
		switch r.Outcome {
		case remediate.OutcomeVerified:
			verified++
			if a, ok := after.byID[r.RuleID]; !ok || a.status != engine.Pass {
				problems = append(problems, fmt.Sprintf("%-14s harden lo dio por reparado y el escaneo siguiente dice %s", r.RuleID, statusOf(a, ok)))
			}
		case remediate.OutcomeFailed, remediate.OutcomeNotEffective:
			problems = append(problems, fmt.Sprintf("%-14s harden: %s%s", r.RuleID, r.Outcome, suffix(r.Message)))
		}
	}
	if verified == 0 {
		problems = append(problems, "harden no reparó ningún control: el ciclo no prueba nada")
	}
	for _, id := range sortedKeys(before.byID) {
		if vol[id] {
			continue
		}
		b := before.byID[id]
		if a, ok := after.byID[id]; b.status == engine.Pass && (!ok || a.status != engine.Pass) {
			problems = append(problems, fmt.Sprintf("%-14s pasaba y tras harden da %s%s", id, statusOf(a, ok), suffix(a.detail)))
		}
		if r, ok := restored.byID[id]; !ok || r.status != b.status {
			problems = append(problems, fmt.Sprintf("%-14s el rollback no lo deja como estaba: antes %s, después %s", id, b.status, statusOf(r, ok)))
		}
	}
	if m.Status != remediate.StatusRolledBack {
		problems = append(problems, fmt.Sprintf("el cambio %s quedó como %q tras el rollback", m.ID, m.Status))
	}
	return problems, verified
}

func statusOf(o observed, ok bool) string {
	if !ok {
		return "nada (no se evaluó)"
	}
	return string(o.status)
}

func suffix(detail string) string {
	if detail == "" {
		return ""
	}
	return " · " + detail
}

func joinStatus(s []engine.Status) string {
	parts := make([]string, len(s))
	for i, st := range s {
		parts[i] = string(st)
	}
	return strings.Join(parts, "|")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
