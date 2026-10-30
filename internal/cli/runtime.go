package cli

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/Ruby570bocadito/bastion/internal/remediate"
)

func runtimeGOOS() string   { return runtime.GOOS }
func runtimeGOARCH() string { return runtime.GOARCH }

// quoteArg escribe un argumento para una orden que el usuario copiará en
// su terminal: entre comillas si tiene espacios u otros caracteres
// especiales (dobles en Windows, simples en Linux).
func quoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\"'$`\\;&|<>()*?#~!{}[]%") {
		return s
	}
	if runtime.GOOS == "windows" {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// checkConfirmTimeout valida --confirm-timeout: el dead-man switch revierte
// remediate.DeadmanMargin después del fin del plazo de confirmación, así que
// un plazo menor no dejaría tiempo para confirmar.
func checkConfirmTimeout(d time.Duration) error {
	if d <= remediate.DeadmanMargin {
		return fmt.Errorf("--confirm-timeout debe ser mayor que %s (p. ej. 2m): es el tiempo para comprobar que sigues pudiendo entrar", remediate.DeadmanMargin)
	}
	return nil
}
