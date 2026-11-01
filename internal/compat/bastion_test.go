package compat

import (
	"path/filepath"
	"testing"

	"github.com/Ruby570bocadito/adarve/internal/engine"
	"github.com/Ruby570bocadito/adarve/internal/exceptions"
	"github.com/Ruby570bocadito/adarve/internal/remediate"
	"github.com/Ruby570bocadito/adarve/internal/report"
)

// Adarve se llamaba Bastion. testdata/bastion reproduce su carpeta de datos
// (excepciones, un informe de escaneo, un análisis de superficie y un
// manifiesto de cambios) con sus esquemas bastion.*/v1. Adarve debe seguir
// leyéndola en toda la versión 1: la historia no se pierde al actualizar y el
// rollback puede deshacer lo que aplicó Bastion (ver docs/16).
func TestReadsBastionData(t *testing.T) {
	dir := filepath.Join("testdata", "bastion")

	ex, err := exceptions.Load(filepath.Join(dir, "exceptions.yaml"))
	if err != nil {
		t.Errorf("excepciones: %v", err)
	} else if len(ex.Exceptions) != 1 || ex.Exceptions[0].Rule != "LNX-SSH-004" {
		t.Errorf("excepciones: %+v", ex.Exceptions)
	}

	reports := filepath.Join(dir, "reports")
	metas, err := report.ListSaved(reports, "web-01")
	if err != nil || len(metas) != 1 {
		t.Fatalf("informes guardados: %+v, %v", metas, err)
	}
	if m := metas[0]; m.ID != "bastion-web-01-20260301-101500" || m.Profile != "linux-server-l1" || m.Score.Value != 50 {
		t.Errorf("informe guardado: %+v", m)
	}
	rep, err := report.LoadSaved(reports, metas[0].ID)
	if err != nil {
		t.Fatalf("informe: %v", err)
	}
	if len(rep.Results) != 2 || rep.Results[0].Rule.ID != "LNX-NET-001" || rep.Results[0].Status != engine.Fail {
		t.Errorf("resultados del informe: %+v", rep.Results)
	}

	surf, err := report.LatestSurface(reports, "web-01")
	if err != nil || surf == nil {
		t.Fatalf("superficie: %v", err)
	}
	if len(surf.Listeners) != 2 || surf.Listeners[0].Port != 22 {
		t.Errorf("superficie: %+v", surf.Listeners)
	}

	m, err := (&remediate.Store{Dir: filepath.Join(dir, "snapshots")}).Load("chg-20260301-102000")
	if err != nil {
		t.Fatalf("manifiesto de cambios: %v", err)
	}
	if len(m.Entries) != 1 {
		t.Fatalf("manifiesto de cambios: %d entradas, quiero 1", len(m.Entries))
	}
	if e := m.Entries[0]; e.Action.Type != "sysctl.set" || e.Action.Params["key"] != "net.ipv4.ip_forward" || e.Before["runtime"] != "1" || !e.Applied {
		t.Errorf("entrada del manifiesto: %+v", e)
	}
}
