// Package rules contiene el paquete oficial de reglas y perfiles de Adarve.
// Se incrusta en el binario: actualizar Adarve actualiza también las reglas.
package rules

import "embed"

// FS contiene las reglas (linux/, windows/) y los perfiles (profiles/).
//
//go:embed linux windows profiles
var FS embed.FS
