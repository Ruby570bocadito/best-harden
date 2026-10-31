# ADR-0002 · Reglas declarativas en YAML

**Estado:** aceptada · **Fecha:** 2026-10

## Contexto
Los controles de hardening cambian a menudo (nuevas versiones de CIS, nuevos ataques) y deben poder revisarlos personas de seguridad que no programan. Además, un paquete de reglas que pueda ejecutar código convierte la herramienta en un vector de ataque.

## Decisión
Las reglas son **datos** en YAML: `check` describe qué leer (probe + parámetros) y qué esperar (operador + valor), con composición `all`/`any`. La lógica de lectura vive en probes de solo lectura escritos en Go. No existe un probe "ejecutar comando".

## Consecuencias
- ✅ Auditables, versionables y validables (`rules lint`, JSON Schema, test en CI).
- ✅ Un paquete de reglas no puede ejecutar código.
- ✅ Las reglas se incrustan en el binario: actualizar Adarve actualiza las reglas.
- ⚠️ Un control que necesite un dato nuevo requiere un probe nuevo (cambio en Go con revisión). Es intencionado.
