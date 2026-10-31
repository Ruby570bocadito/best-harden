package engine

import (
	"sort"
	"time"

	"github.com/Ruby570bocadito/adarve/internal/platform"
	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

// Counts agrupa resultados por estado.
type Counts struct {
	Total      int `json:"total"`
	Passed     int `json:"passed"`
	Failed     int `json:"failed"`
	Errors     int `json:"errors"`
	Skipped    int `json:"skipped"`
	Exceptions int `json:"exceptions"`
	NA         int `json:"na"`
}

func (c *Counts) add(s Status) {
	c.Total++
	switch s {
	case Pass:
		c.Passed++
	case Fail:
		c.Failed++
	case Error:
		c.Errors++
	case Skipped:
		c.Skipped++
	case Exception:
		c.Exceptions++
	default:
		c.NA++
	}
}

// CategoryScore es la puntuación de una categoría de controles.
type CategoryScore struct {
	Name   string `json:"name"`
	Value  int    `json:"value"`
	Scored bool   `json:"scored"` // false: ningún control evaluado (Value 0)
	Counts
}

// Score resume la postura de seguridad del equipo.
//
// Valor = Σ peso(superados) / Σ peso(superados + fallidos) × 100, con pesos
// crítico 10, alto 5, medio 3, bajo 1. Los errores, los no evaluados por
// falta de privilegios, las excepciones vigentes y los "no aplica" no
// cuentan; si hay errores o no evaluados la puntuación se marca como parcial.
// Si no hay ningún control superado ni fallido (todo error, no evaluado o
// no aplica) no hay puntuación: Scored es false, Value 0 y Grade "N/A".
type Score struct {
	Value      int               `json:"value"`
	Grade      string            `json:"grade"`
	Scored     bool              `json:"scored"`
	Partial    bool              `json:"partial"`
	Counts                       //
	BySeverity map[string]Counts `json:"by_severity"`
	ByCategory []CategoryScore   `json:"by_category"`
}

// ComputeScore calcula la puntuación a partir de los resultados.
func ComputeScore(results []Result) Score {
	s := Score{BySeverity: map[string]Counts{}}
	var got, max int
	cats := map[string]*CategoryScore{}
	catW := map[string][2]int{}
	for _, r := range results {
		s.Counts.add(r.Status)
		sev := s.BySeverity[string(r.Rule.Severity)]
		sev.add(r.Status)
		s.BySeverity[string(r.Rule.Severity)] = sev

		c := cats[r.Rule.Category]
		if c == nil {
			c = &CategoryScore{Name: r.Rule.Category}
			cats[r.Rule.Category] = c
		}
		c.add(r.Status)

		w := r.Rule.Severity.Weight()
		cw := catW[r.Rule.Category]
		switch r.Status {
		case Pass:
			got += w
			max += w
			cw[0] += w
			cw[1] += w
		case Fail:
			max += w
			cw[1] += w
		}
		catW[r.Rule.Category] = cw
	}
	s.Value, s.Scored = pct(got, max)
	s.Grade = grade(s.Value)
	if !s.Scored {
		s.Grade = "N/A"
	}
	s.Partial = s.Errors > 0 || s.Skipped > 0
	for name, c := range cats {
		c.Value, c.Scored = pct(catW[name][0], catW[name][1])
		s.ByCategory = append(s.ByCategory, *c)
	}
	sort.Slice(s.ByCategory, func(i, j int) bool {
		if s.ByCategory[i].Value != s.ByCategory[j].Value {
			return s.ByCategory[i].Value < s.ByCategory[j].Value
		}
		return s.ByCategory[i].Name < s.ByCategory[j].Name
	})
	return s
}

// pct es el porcentaje redondeado; ok es false si no hay nada que puntuar.
func pct(got, max int) (int, bool) {
	if max == 0 {
		return 0, false
	}
	return (got*100 + max/2) / max, true
}

func grade(v int) string {
	switch {
	case v >= 90:
		return "A"
	case v >= 80:
		return "B"
	case v >= 70:
		return "C"
	case v >= 60:
		return "D"
	}
	return "F"
}

// Report es el resultado completo de un escaneo. Es el formato JSON estable
// que consumen el informe HTML, la futura UI y las integraciones.
type Report struct {
	Schema     string        `json:"schema"`
	Tool       ToolInfo      `json:"tool"`
	Host       platform.Info `json:"host"`
	Profile    *rule.Profile `json:"profile"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	DurationMs int64         `json:"duration_ms"`
	Score      Score         `json:"score"`
	Results    []Result      `json:"results"`
	// Changes compara con el último escaneo guardado del mismo perfil.
	Changes *Changes `json:"changes,omitempty"`
}

// ToolInfo identifica la versión de Adarve que generó el informe.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// SchemaVersion del formato de informe.
const SchemaVersion = "adarve.report/v1"
