//go:build windows

package notify

import (
	"strings"

	"golang.org/x/sys/windows/svc/eventlog"
)

// source es el origen de los eventos en el registro Aplicación.
const source = "Adarve"

// Identificadores de evento (EventCreate.exe, que da el texto de los
// mensajes, admite del 1 al 1000).
const (
	eventInfo    = 100
	eventWarning = 200
	eventError   = 300
)

// LocalName describe dónde quedan los avisos en este sistema.
const LocalName = "Visor de eventos (Registros de Windows › Aplicación, origen Adarve)"

// InstallLocal registra el origen Adarve en el registro Aplicación (requiere
// privilegios). Si ya existe, no hace nada.
func InstallLocal() error {
	err := eventlog.InstallAsEventCreate(source, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil && strings.Contains(err.Error(), "already exists") {
		return nil
	}
	return err
}

// Local anota el aviso en el Visor de eventos.
func Local(ev Event) error {
	_ = InstallLocal()
	l, err := eventlog.Open(source)
	if err != nil {
		return err
	}
	defer l.Close()
	msg := truncate(ev.Text(), 30000)
	switch ev.Level {
	case LevelError:
		return l.Error(eventError, msg)
	case LevelWarning:
		return l.Warning(eventWarning, msg)
	}
	return l.Info(eventInfo, msg)
}
