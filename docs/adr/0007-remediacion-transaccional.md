# ADR-0007 · Remediación transaccional con acciones tipadas

**Estado:** aceptada · **Fecha:** 2026-10

## Contexto
Endurecer un sistema en producción da miedo por una razón: los cambios rompen cosas y deshacerlos a mano es lento y propenso a errores. Las herramientas basadas en scripts no saben qué había antes ni comprueban si el cambio surtió efecto (una GPO o Tamper Protection pueden anularlo en silencio).

## Decisión
- Cada corrección se expresa como una **acción tipada** con cuatro operaciones: `Capture` (solo lectura), `Describe`, `Apply` y `Restore`. Hay 13 tipos y ninguno ejecuta comandos libres.
- `harden` es una **simulación por defecto**; `--apply` aplica.
- Por cada acción se guarda el estado previo en un **manifiesto en disco antes de aplicar** (registro previo).
- Tras aplicar, se **reevalúa el control**: si no se cumple, se revierte. Un cambio que no surte efecto es peor que no hacer nada, porque da una falsa sensación de seguridad.
- Los cambios se agrupan en **olas por riesgo de rotura**, declarado en cada regla.
- Los cambios que pueden cortar el acceso remoto llevan un **dead-man switch** en un proceso independiente (desde el [ADR-0011](0011-dead-man-switch-persistente.md), una tarea del sistema que también sobrevive a un reinicio).

## Consecuencias
- ✅ Rollback exacto, también desde otro proceso o tras un corte (`adarve rollback`).
- ✅ Resultados honestos: "aplicado y verificado", "sin efecto (revertido)", "error (revertido)".
- ✅ La CI prueba el ciclo completo en sistemas reales desechables.
- ⚠️ Cada nuevo tipo de cambio requiere implementar y probar su `Restore`. Es intencionado.
- ⚠️ Algunos cambios (BitLocker, Secure Boot, LAPS) seguirán siendo manuales.
