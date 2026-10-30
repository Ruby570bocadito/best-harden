// Package engine evalúa reglas contra el sistema y calcula la postura.
package engine

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/exceptions"
	"github.com/Ruby570bocadito/bastion/internal/probes"
	"github.com/Ruby570bocadito/bastion/pkg/rule"
)

// Status es el resultado de una comprobación.
type Status string

const (
	Pass  Status = "pass"
	Fail  Status = "fail"
	Error Status = "error"
	NA    Status = "na"
	// Skipped: no se pudo evaluar por falta de privilegios. Como los
	// errores, no cuenta en la puntuación, que se marca como parcial.
	Skipped Status = "skipped"
	// Exception: el control falla, pero hay una excepción vigente que lo
	// acepta. No cuenta en la puntuación ni entra en "harden".
	Exception Status = "exception"
)

// Eval es la evaluación de una comprobación (hoja o compuesta).
type Eval struct {
	Status   Status `json:"status"`
	Label    string `json:"label,omitempty"`
	Probe    string `json:"probe,omitempty"`
	Field    string `json:"field,omitempty"`
	Actual   string `json:"actual,omitempty"`
	Expected string `json:"expected,omitempty"`
	Source   string `json:"source,omitempty"`
	Message  string `json:"message,omitempty"`
	Children []Eval `json:"children,omitempty"`
}

// Result es la evaluación de una regla completa.
type Result struct {
	Rule *rule.Rule `json:"rule"`
	Eval
	DurationMs int64 `json:"duration_ms"`
	// Exception es la excepción que cubre el control: vigente (el estado es
	// "exception") o caducada (el control vuelve a contar como fallido).
	Exception *ExceptionRef `json:"exception,omitempty"`
}

// ExceptionRef es la excepción aplicada a un resultado.
type ExceptionRef struct {
	exceptions.Entry
	Expired bool `json:"expired"`
}

// Engine evalúa reglas en paralelo.
type Engine struct {
	Concurrency int
	// HostTags son las etiquetas del equipo; se usan para el campo requires.
	HostTags []string
}

// New crea un motor con la concurrencia por defecto.
func New() *Engine {
	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}
	if n < 2 {
		n = 2
	}
	return &Engine{Concurrency: n}
}

// Run evalúa las reglas. progress (opcional) recibe (hechas, total).
func (e *Engine) Run(ctx context.Context, rules []*rule.Rule, progress func(done, total int)) []Result {
	ctx = probes.WithSession(ctx, probes.NewSession())
	results := make([]Result, len(rules))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var done int64
	for w := 0; w < e.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				start := time.Now()
				var ev Eval
				if req := rules[i].MissingRequirement(e.HostTags); req != "" {
					msg := rule.RequirementMessages[req]
					if msg == "" {
						msg = "requiere la plataforma " + req
					}
					ev = Eval{Status: NA, Message: msg}
				} else {
					ev = e.evalCheck(ctx, rules[i].Check)
				}
				results[i] = Result{Rule: rules[i], Eval: ev, DurationMs: time.Since(start).Milliseconds()}
				n := atomic.AddInt64(&done, 1)
				if progress != nil {
					progress(int(n), len(rules))
				}
			}
		}()
	}
	for i := range rules {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	SortResults(results)
	return results
}

// SortResults ordena por estado, severidad e ID.
func SortResults(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if statusRank(a.Status) != statusRank(b.Status) {
			return statusRank(a.Status) < statusRank(b.Status)
		}
		if a.Rule.Severity.Rank() != b.Rule.Severity.Rank() {
			return a.Rule.Severity.Rank() < b.Rule.Severity.Rank()
		}
		return a.Rule.ID < b.Rule.ID
	})
}

// ApplyExceptions marca como "exception" los controles fallidos con una
// excepción vigente para host y anota las caducadas (que siguen fallando).
// Los controles que pasan, no aplican o no se pudieron leer no cambian.
// Devuelve las excepciones caducadas encontradas.
func ApplyExceptions(results []Result, f *exceptions.File, host string, now time.Time) []Result {
	if f == nil || len(f.Exceptions) == 0 {
		return nil
	}
	var expired []Result
	for i := range results {
		r := &results[i]
		if r.Status != Fail {
			continue
		}
		e, isExpired := f.Find(r.Rule.ID, host, now)
		if e == nil {
			continue
		}
		r.Exception = &ExceptionRef{Entry: *e, Expired: isExpired}
		if isExpired {
			expired = append(expired, *r)
			continue
		}
		r.Status = Exception
	}
	SortResults(results)
	return expired
}

func statusRank(s Status) int {
	switch s {
	case Fail:
		return 0
	case Error:
		return 1
	case Skipped:
		return 2
	case Exception:
		return 3
	case Pass:
		return 4
	}
	return 5
}

func (e *Engine) evalCheck(ctx context.Context, c rule.Check) (ev Eval) {
	defer func() {
		// Un fallo inesperado en un probe nunca debe tumbar el escaneo.
		if r := recover(); r != nil {
			ev = Eval{Status: Error, Message: fmt.Sprintf("error interno: %v", r)}
		}
	}()
	switch {
	case len(c.All) > 0:
		return e.evalComposite(ctx, c, c.All, true)
	case len(c.Any) > 0:
		return e.evalComposite(ctx, c, c.Any, false)
	}
	return e.evalLeaf(ctx, c)
}

func (e *Engine) evalComposite(ctx context.Context, c rule.Check, children []rule.Check, all bool) Eval {
	ev := Eval{Label: c.Label}
	var pass, fail, errs, skipped, na int
	for _, ch := range children {
		r := e.evalCheck(ctx, ch)
		ev.Children = append(ev.Children, r)
		switch r.Status {
		case Pass:
			pass++
		case Fail:
			fail++
		case Error:
			errs++
		case Skipped:
			skipped++
		default:
			na++
		}
	}
	switch {
	case all && fail > 0:
		ev.Status = Fail
	case all && errs > 0:
		ev.Status = Error
	case all && skipped > 0:
		ev.Status = Skipped
	case all && pass > 0:
		ev.Status = Pass
	case !all && pass > 0:
		ev.Status = Pass
	// En "any", un hijo que no se pudo evaluar podría haber cumplido: el
	// resultado es desconocido (error / no evaluado), no un fallo.
	case !all && errs > 0:
		ev.Status = Error
	case !all && skipped > 0:
		ev.Status = Skipped
	case !all && fail > 0:
		ev.Status = Fail
	default:
		ev.Status = NA
	}
	// Resumen legible para la fila principal del informe.
	for _, ch := range ev.Children {
		if ch.Status == ev.Status || (ev.Status == NA && ch.Message != "") {
			if ev.Message == "" {
				ev.Message = ch.Message
			}
			if ev.Actual == "" && ch.Status != Pass {
				ev.Actual, ev.Expected, ev.Source = ch.Actual, ch.Expected, ch.Source
			}
		}
	}
	if ev.Status == Pass {
		ev.Actual, ev.Expected = "", ""
		if len(ev.Children) > 0 {
			first := ev.Children[0]
			for _, ch := range ev.Children {
				if ch.Status == Pass {
					first = ch
					break
				}
			}
			ev.Actual, ev.Expected, ev.Source = first.Actual, first.Expected, first.Source
		}
	}
	return ev
}

func (e *Engine) evalLeaf(ctx context.Context, c rule.Check) Eval {
	ev := Eval{Label: c.Label, Probe: c.Probe, Expected: describeExpected(c.Op, c.Expected)}
	p, ok := probes.Get(c.Probe)
	if !ok {
		ev.Status, ev.Message = NA, fmt.Sprintf("el probe %q no está disponible en esta plataforma", c.Probe)
		return ev
	}
	obs, err := p.Collect(ctx, probes.Params(c.Params))
	if err != nil {
		if reason, ok := probes.AsNotApplicable(err); ok {
			ev.Status, ev.Message = NA, reason
			return ev
		}
		if reason, ok := probes.AsPrivilege(err); ok {
			ev.Status, ev.Message = Skipped, reason
			return ev
		}
		ev.Status, ev.Message = Error, err.Error()
		return ev
	}
	ev.Source = obs.Source
	field := c.Field
	if field == "" {
		field = p.DefaultField()
	}
	ev.Field = field

	switch c.Op {
	case "exists", "absent":
		ev.Actual = map[bool]string{true: "presente", false: "ausente"}[obs.Found]
		if obs.Found == (c.Op == "exists") {
			ev.Status = Pass
		} else {
			ev.Status = Fail
		}
		return ev
	}

	var actual any
	usedDefault := false
	found := obs.Found
	if found {
		actual, found = lookupField(obs.Fields, field)
	}
	if !found {
		switch {
		case c.HasDefault:
			actual, usedDefault = c.Default, true
			ev.Message = "no configurado explícitamente: se aplica el valor por defecto del sistema"
		case c.OnMissing == "pass":
			ev.Status, ev.Actual = Pass, "no presente"
			return ev
		case c.OnMissing == "na":
			ev.Status, ev.Actual, ev.Message = NA, "no presente", "el elemento no existe en este equipo"
			return ev
		default:
			ev.Status, ev.Actual = Fail, "no configurado"
			return ev
		}
	}

	ok, err = compareEach(c.Op, actual, c.Expected, c.Each)
	if err != nil {
		ev.Status, ev.Message, ev.Actual = Error, err.Error(), formatValue(actual)
		return ev
	}
	if c.Each != "" {
		ev.Actual = formatEach(c.Op, actual, c.Expected)
	} else {
		ev.Actual = formatValue(actual)
	}
	if usedDefault {
		ev.Actual += " (por defecto)"
	}
	if ok {
		ev.Status = Pass
	} else {
		ev.Status = Fail
	}
	return ev
}

// compareEach aplica el operador a cada elemento cuando each = all|any.
func compareEach(op string, actual, expected any, each string) (bool, error) {
	if each == "" {
		return compare(op, actual, expected)
	}
	items := toList(actual)
	if len(items) == 0 {
		return false, nil
	}
	for _, it := range items {
		ok, err := compare(op, it, expected)
		if err != nil {
			return false, err
		}
		if each == "any" && ok {
			return true, nil
		}
		if each == "all" && !ok {
			return false, nil
		}
	}
	return each == "all", nil
}

// formatEach resume una lista evaluada elemento a elemento: agrupa los
// valores repetidos y dice cuántos cumplen, p. ej. "0 ×8, 2 (cumplen 1 de 9)".
func formatEach(op string, actual, expected any) string {
	items := toList(actual)
	if len(items) <= 1 {
		return formatValue(actual)
	}
	var order []string
	count := map[string]int{}
	ok := 0
	for _, it := range items {
		v := formatValue(it)
		if v == "" {
			v = "(vacío)"
		}
		if count[v] == 0 {
			order = append(order, v)
		}
		count[v]++
		if pass, err := compare(op, it, expected); err == nil && pass {
			ok++
		}
	}
	parts := make([]string, len(order))
	for i, v := range order {
		parts[i] = v
		if count[v] > 1 {
			parts[i] = fmt.Sprintf("%s ×%d", v, count[v])
		}
	}
	return fmt.Sprintf("%s (cumplen %d de %d)", strings.Join(parts, ", "), ok, len(items))
}
