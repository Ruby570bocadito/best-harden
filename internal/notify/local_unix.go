//go:build !windows

package notify

import (
	"fmt"
	"log/syslog"
)

// LocalName describe dónde quedan los avisos en este sistema.
const LocalName = "syslog (journalctl -t adarve)"

// InstallLocal no necesita nada en Unix.
func InstallLocal() error { return nil }

// Local anota el aviso en syslog (journald lo recoge), en una línea.
func Local(ev Event) error {
	prio := syslog.LOG_INFO
	switch ev.Level {
	case LevelError:
		prio = syslog.LOG_ERR
	case LevelWarning:
		prio = syslog.LOG_WARNING
	}
	w, err := syslog.New(prio|syslog.LOG_DAEMON, "adarve")
	if err != nil {
		return fmt.Errorf("no hay servicio de syslog en este equipo (%v)", err)
	}
	defer w.Close()
	msg := truncate(ev.OneLine(), 8000)
	switch ev.Level {
	case LevelError:
		return w.Err(msg)
	case LevelWarning:
		return w.Warning(msg)
	}
	return w.Info(msg)
}
