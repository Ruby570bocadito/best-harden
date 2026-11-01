package schedule

import (
	"context"
	"fmt"
	"regexp"
)

// Deadman arma el dead-man switch de un cambio de hardening como tarea del
// sistema: «adarve deadman <id>» arranca ya, fuera de la sesión del usuario,
// y otra vez en cada inicio del equipo hasta que se desarma. Así sobrevive
// al cierre de la sesión SSH o RDP y a un reinicio antes del plazo.
type Deadman interface {
	ArmDeadman(ctx context.Context, exe, id string) error
	// DisarmDeadman quita el arranque en cada inicio. Con stop, también
	// detiene la ejecución en curso; sin él (cuando lo pide el propio
	// dead-man switch al terminar), la deja acabar.
	DisarmDeadman(ctx context.Context, id string, stop bool) error
}

// reDeadmanID es el formato de los ID de cambio (chg-AAAAMMDD-HHMMSS[-N]):
// forma parte del nombre de la unidad o de la tarea.
var reDeadmanID = regexp.MustCompile(`^chg-[0-9]{8}-[0-9]{6}(-[0-9]+)?$`)

func checkDeadmanID(id string) error {
	if !reDeadmanID.MatchString(id) {
		return fmt.Errorf("ID de cambio inválido: %q", id)
	}
	return nil
}
