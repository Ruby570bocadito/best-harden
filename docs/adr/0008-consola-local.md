# ADR-0008 · Consola local en 127.0.0.1, con token y de solo lectura

**Estado:** aceptada · **Fecha:** 2026-10

## Contexto
El informe HTML ([ADR-0006](0006-informe-html-autocontenido.md)) es una foto de un escaneo. Para trabajar con un equipo hace falta más: ver cómo evoluciona la postura, comparar escaneos, revisar el plan de hardening por olas y las excepciones, y volver a escanear sin salir del navegador. La consola de flota llegará en la fase 3; mientras tanto, se quiere algo útil en modo standalone.

Un servidor HTTP local abre superficie de ataque nueva en una herramienta que suele ejecutarse como administrador:
- otra web abierta en el navegador puede intentar llamar a `http://127.0.0.1:<puerto>` (CSRF, lectura de respuestas);
- un dominio del atacante que resuelve a 127.0.0.1 puede saltarse la política del mismo origen (DNS rebinding);
- en un equipo compartido, otro usuario local puede conectarse al puerto.

## Decisión
`adarve ui` levanta un servidor embebido en el binario con estas reglas:

1. **Solo loopback.** Escucha en `127.0.0.1`, en un puerto libre al azar (o `--port`).
2. **Token por sesión.** 256 bits aleatorios que solo conoce quien lanzó el comando: van en la dirección que se abre (`?t=`) y la página los guarda en `sessionStorage` y los quita de la barra de direcciones. Toda la API exige la cabecera `X-Adarve-Token` (comparación en tiempo constante). El informe HTML incrustado, que va en un iframe, lo recibe en la URL.
3. **Host y Origin.** Se rechaza cualquier `Host` que no sea `127.0.0.1`, `localhost` o `::1` (DNS rebinding) y cualquier petición de escritura con un `Origin` ajeno. No se responde a CORS: una web maliciosa no puede enviar la cabecera del token ni leer respuestas.
4. **CSP estricta con nonce**, `frame-ancestors 'none'` (el informe incrustado, `'self'`), `nosniff`, `no-referrer`, `no-store`, COOP/CORP. Los datos del sistema auditado se insertan siempre con `textContent`.
5. **Solo lee y escanea.** Desde la consola se puede escanear y calcular el plan de hardening (simulación), pero no aplicar cambios, deshacerlos ni editar excepciones. Eso sigue en la terminal, donde están la confirmación, la instantánea, el dead-man switch y el control de privilegios.
6. **Sin dependencias.** HTML, CSS y JavaScript escritos a mano y embebidos (`internal/ui/assets/ui.html`), con los mismos tokens de diseño que el informe. Gráficos en SVG generado con DOM.

El historial son los informes JSON que ya guarda `scan --save`. La consola guarda los suyos en el mismo directorio, así que no hay una segunda base de datos.

## Consecuencias
- ✅ Tendencia, plan por olas, historial de escaneos y de cambios, y excepciones en el navegador, sin instalar nada más.
- ✅ La superficie nueva está acotada: sin token no hay datos, y aunque alguien lo robara solo podría leer y escanear.
- ✅ Funciona en servidores sin escritorio con un túnel SSH (`--port` fijo + `ssh -L`).
- ⚠️ El token aparece en la terminal y en el historial del navegador. Cualquiera con acceso a esa terminal ya tiene los privilegios de quien la abrió, así que no se considera una pérdida de seguridad.
- ⚠️ Aplicar cambios desde la UI queda para la consola de flota (fase 3), con autenticación real, RBAC y aprobación a cuatro ojos.
