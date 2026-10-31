# ADR-0004 · Sin ejecución arbitraria de comandos

**Estado:** aceptada · **Fecha:** 2026-10

## Contexto
Adarve se ejecuta como SYSTEM/root en toda la flota. Si el servidor o un paquete de reglas pudieran ordenar la ejecución de comandos arbitrarios, comprometer Adarve equivaldría a comprometer toda la organización (como ocurre con muchas herramientas RMM).

## Decisión
- Las reglas no pueden contener comandos que se ejecuten. Los campos `remediation.commands` son **texto informativo** para el operador y Adarve nunca los ejecuta.
- Los probes solo ejecutan comandos fijados en el código, con ruta absoluta en Windows. El probe `ps` acepta solo nombres de una lista blanca.
- La remediación automática (fase 2) usará **acciones tipadas** (`registry.set`, `sysctl.set`...) sin un tipo genérico "ejecutar".
- El servidor (fase 3) solo enviará trabajos tipados: escanear con un perfil o aplicar un plan aprobado de un paquete firmado.

## Consecuencias
- ✅ Adarve no puede convertirse en un C2 ni en una vía de movimiento lateral.
- ✅ Revisión de seguridad acotada: basta con auditar probes y remediadores.
- ⚠️ Algunas remediaciones exóticas no serán automatizables; quedarán como guía manual.
