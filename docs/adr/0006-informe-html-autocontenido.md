# ADR-0006 · Informe HTML autocontenido como primera UI

**Estado:** aceptada · **Fecha:** 2026-10

## Contexto
Se quiere una interfaz cuidada desde el principio, pero la consola web de flota (React + servidor) llegará en la fase 3.

## Decisión
Un informe HTML **de un único fichero** generado por el binario: datos incrustados como JSON, JavaScript sin dependencias, temas claro y oscuro, filtros, evidencias y remediación. Sin CDNs ni recursos externos. CSP con nonce y renderizado solo con `textContent`.

## Consecuencias
- ✅ Funciona sin conexión, se envía por correo y se imprime a PDF.
- ✅ Valida el diseño visual (tokens, paleta de estado, jerarquía) que heredará la consola web.
- ✅ El JSON incrustado es el mismo `adarve.report/v1`: la futura UI reutiliza los datos.
- ⚠️ Plantilla HTML/JS escrita a mano; cuando exista `ui/` (React), el informe podrá generarse desde ese mismo código.
