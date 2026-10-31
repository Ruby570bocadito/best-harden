package engine

import (
	"sort"
	"time"

	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// RuleChange es un control que ha cambiado de estado desde el escaneo
// anterior.
type RuleChange struct {
	ID       string        `json:"id"`
	Title    string        `json:"title"`
	Severity rule.Severity `json:"severity"`
	Before   Status        `json:"before"`
	After    Status        `json:"after"`
}

// Changes compara el escaneo con el último guardado del mismo equipo y
// perfil: los controles que han empeorado (una actualización, una GPO o
// alguien que ha deshecho un ajuste) y los que se han corregido.
type Changes struct {
	Since       time.Time    `json:"since"`
	ScoreBefore int          `json:"score_before"`
	Regressions []RuleChange `json:"regressions"` // superado → fallido
	Fixed       []RuleChange `json:"fixed"`       // fallido → superado
}

// Diff compara dos escaneos. Solo cuenta los controles evaluados en ambos;
// los errores, los no evaluados y las excepciones no son cambios.
func Diff(prev, cur *Report) *Changes {
	ch := &Changes{Since: prev.FinishedAt, ScoreBefore: prev.Score.Value, Regressions: []RuleChange{}, Fixed: []RuleChange{}}
	before := map[string]Status{}
	for _, r := range prev.Results {
		if r.Rule != nil {
			before[r.Rule.ID] = r.Status
		}
	}
	for _, r := range cur.Results {
		if r.Rule == nil {
			continue
		}
		old, ok := before[r.Rule.ID]
		if !ok {
			continue
		}
		c := RuleChange{ID: r.Rule.ID, Title: r.Rule.Title, Severity: r.Rule.Severity, Before: old, After: r.Status}
		switch {
		case old == Pass && r.Status == Fail:
			ch.Regressions = append(ch.Regressions, c)
		case old == Fail && r.Status == Pass:
			ch.Fixed = append(ch.Fixed, c)
		}
	}
	for _, l := range [][]RuleChange{ch.Regressions, ch.Fixed} {
		sort.SliceStable(l, func(i, j int) bool {
			if l[i].Severity.Rank() != l[j].Severity.Rank() {
				return l[i].Severity.Rank() < l[j].Severity.Rank()
			}
			return l[i].ID < l[j].ID
		})
	}
	return ch
}
