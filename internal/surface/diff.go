package surface

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// Tipos de cambio entre dos análisis.
const (
	ChangeNew      = "new"      // un servicio empieza a escuchar en la red
	ChangeGone     = "gone"     // deja de escuchar
	ChangeWorse    = "worse"    // el firewall lo deja más abierto
	ChangeBetter   = "better"   // el firewall lo limita más
	ChangeFinding  = "finding"  // hallazgo nuevo
	ChangeResolved = "resolved" // hallazgo resuelto
)

// Change es un cambio de exposición desde el análisis anterior.
type Change struct {
	Kind     string        `json:"kind"`
	Subject  string        `json:"subject"` // 8766/tcp o el ID del hallazgo
	Process  string        `json:"process,omitempty"`
	Before   string        `json:"before,omitempty"` // estado del firewall antes
	After    string        `json:"after,omitempty"`
	Severity rule.Severity `json:"severity,omitempty"`
	Title    string        `json:"title"`
}

// Bad indica si el cambio aumenta la exposición.
func (c Change) Bad() bool {
	return c.Kind == ChangeNew || c.Kind == ChangeWorse || c.Kind == ChangeFinding
}

// Changes compara el análisis con el último guardado.
type Changes struct {
	Since       time.Time `json:"since"`
	ScoreBefore int       `json:"score_before"`
	Items       []Change  `json:"items"`
}

// Diff compara dos análisis del mismo equipo: servicios que aparecen o
// desaparecen de la red, cambios del firewall y hallazgos nuevos o
// resueltos. Primero lo que empeora.
func Diff(prev, cur *Report) *Changes {
	ch := &Changes{Since: prev.FinishedAt, ScoreBefore: prev.Score, Items: []Change{}}
	before, after := exposedPorts(prev), exposedPorts(cur)
	for _, k := range sortedKeys(after) {
		p := after[k]
		subject := fmt.Sprintf("%d/%s", p.Port, p.Proto)
		old, existed := before[k]
		switch {
		case !existed:
			ch.Items = append(ch.Items, Change{Kind: ChangeNew, Subject: subject, Process: p.Process, After: stateLabel(p),
				Title: fmt.Sprintf("%s (%s) escucha en la red: %s", subject, procName(p), stateLabel(p))})
		case stateRank(p) > stateRank(old):
			ch.Items = append(ch.Items, Change{Kind: ChangeWorse, Subject: subject, Process: p.Process, Before: stateLabel(old), After: stateLabel(p),
				Title: fmt.Sprintf("%s (%s): %s → %s", subject, procName(p), stateLabel(old), stateLabel(p))})
		case stateRank(p) < stateRank(old):
			ch.Items = append(ch.Items, Change{Kind: ChangeBetter, Subject: subject, Process: p.Process, Before: stateLabel(old), After: stateLabel(p),
				Title: fmt.Sprintf("%s (%s): %s → %s", subject, procName(p), stateLabel(old), stateLabel(p))})
		}
	}
	for _, k := range sortedKeys(before) {
		if _, ok := after[k]; !ok {
			p := before[k]
			subject := fmt.Sprintf("%d/%s", p.Port, p.Proto)
			ch.Items = append(ch.Items, Change{Kind: ChangeGone, Subject: subject, Process: p.Process, Before: stateLabel(p),
				Title: fmt.Sprintf("%s (%s) ya no escucha en la red", subject, procName(p))})
		}
	}
	oldF, newF := findingMap(prev), findingMap(cur)
	for _, k := range sortedKeys(newF) {
		if _, ok := oldF[k]; !ok {
			f := newF[k]
			ch.Items = append(ch.Items, Change{Kind: ChangeFinding, Subject: f.ID, Severity: f.Severity, Title: f.Title})
		}
	}
	for _, k := range sortedKeys(oldF) {
		if _, ok := newF[k]; !ok {
			f := oldF[k]
			ch.Items = append(ch.Items, Change{Kind: ChangeResolved, Subject: f.ID, Severity: f.Severity, Title: f.Title})
		}
	}
	order := map[string]int{ChangeWorse: 0, ChangeNew: 1, ChangeFinding: 2, ChangeBetter: 3, ChangeGone: 4, ChangeResolved: 5}
	sort.SliceStable(ch.Items, func(i, j int) bool { return order[ch.Items[i].Kind] < order[ch.Items[j].Kind] })
	return ch
}

// exposedPorts indexa los servicios en la red por protocolo, puerto y
// proceso (el PID cambia en cada arranque).
func exposedPorts(r *Report) map[string]Port {
	out := map[string]Port{}
	for _, p := range r.Ports {
		if p.Scope != ScopeNetwork || p.Ephemeral {
			continue
		}
		out[fmt.Sprintf("%s/%05d/%s", p.Proto, p.Port, strings.ToLower(p.Process))] = p
	}
	return out
}

// findingMap indexa los hallazgos por lo que los identifica de forma
// estable. Los de un puerto o un recurso compartido, por ID y asunto. Los
// que agrupan varios puertos o programas (NetBIOS, Sunshine, programas
// abiertos) o varias reglas (reglas de usuario), solo por ID: su asunto
// cambia al cerrar uno de ellos (o al empezar a transmitir) y no es un
// hallazgo nuevo; lo que cambia en sus puertos ya lo cuentan los cambios de
// puertos. Cada regla que lo permite todo y cada programa con una firma que
// no vale es un hallazgo propio, distinguido por su título.
func findingMap(r *Report) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range r.Findings {
		key := f.ID + "|" + f.Subject
		_, group := groups[strings.ToLower(strings.TrimPrefix(f.ID, "SURF-"))]
		switch {
		case group, f.ID == "SURF-APPS-OPEN", f.ID == "SURF-FW-USERALLOWALL", f.ID == "SURF-UNSIGNED", f.ID == "SURF-UNPACKAGED":
			key = f.ID
		case f.ID == "SURF-FW-ALLOWALL", f.ID == "SURF-BADSIG":
			key = f.ID + "|" + f.Title
		}
		out[key] = f
	}
	return out
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// stateRank ordena los estados del firewall de menos a más expuesto. Sin
// evaluar el firewall, el puerto cuenta como abierto.
func stateRank(p Port) int {
	switch p.Firewall {
	case FirewallFiltered:
		return 0
	case FirewallLimited:
		return 1
	}
	return 2
}

func stateLabel(p Port) string {
	switch p.Firewall {
	case FirewallFiltered:
		return "filtrado"
	case FirewallLimited:
		return "limitado: " + p.FirewallLimit
	case FirewallOpen:
		return "abierto a cualquiera"
	}
	return "sin evaluar el firewall"
}

func procName(p Port) string {
	if p.Process == "" {
		return "proceso desconocido"
	}
	return p.Process
}
