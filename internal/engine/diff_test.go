package engine

import (
	"testing"
	"time"

	"github.com/Ruby570bocadito/adarve/pkg/rule"
)

func TestDiffReports(t *testing.T) {
	r := func(id string, sev rule.Severity) *rule.Rule {
		return &rule.Rule{ID: id, Title: "Control " + id, Severity: sev}
	}
	res := func(rl *rule.Rule, st Status) Result { return Result{Rule: rl, Eval: Eval{Status: st}} }
	llmnr, smb, wdigest, laps, nuevo, err := r("WIN-NET-006", rule.SevHigh), r("WIN-NET-003", rule.SevHigh), r("WIN-CRED-001", rule.SevCritical),
		r("WIN-ACC-006", rule.SevMedium), r("WIN-SYS-006", rule.SevHigh), r("WIN-DEF-003", rule.SevMedium)
	ayer := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	prev := &Report{FinishedAt: ayer, Score: Score{Value: 80}, Results: []Result{
		res(llmnr, Pass), res(smb, Fail), res(wdigest, Pass), res(laps, Fail), res(err, Pass),
	}}
	cur := &Report{Score: Score{Value: 70}, Results: []Result{
		res(llmnr, Fail),   // empeora
		res(smb, Pass),     // se corrige
		res(wdigest, Fail), // empeora (crítico: va primero)
		res(laps, Exception),
		res(err, Error),  // un error no es un empeoramiento
		res(nuevo, Fail), // regla nueva: no estaba antes
	}}
	ch := Diff(prev, cur)
	if !ch.Since.Equal(ayer) || ch.ScoreBefore != 80 {
		t.Errorf("cabecera: %+v", ch)
	}
	if len(ch.Regressions) != 2 || ch.Regressions[0].ID != "WIN-CRED-001" || ch.Regressions[1].ID != "WIN-NET-006" {
		t.Errorf("empeorados: %+v", ch.Regressions)
	}
	if len(ch.Fixed) != 1 || ch.Fixed[0].ID != "WIN-NET-003" || ch.Fixed[0].Before != Fail || ch.Fixed[0].After != Pass {
		t.Errorf("corregidos: %+v", ch.Fixed)
	}
	if same := Diff(cur, cur); same.Regressions == nil || same.Fixed == nil || len(same.Regressions)+len(same.Fixed) != 0 {
		t.Errorf("sin cambios: %+v", same)
	}
}
