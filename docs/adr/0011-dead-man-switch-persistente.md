# ADR-0011 · Dead-man switch como tarea del sistema

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
`harden --include-remote` aplica cambios que pueden cortar SSH o RDP. El dead-man switch los deshace si nadie confirma desde una sesión nueva antes del plazo. Hasta ahora era un proceso independiente que lanzaba `harden` (`setsid` en Linux, `DETACHED_PROCESS` en Windows). Sobrevivía al cierre de la terminal, pero no a un reinicio. En Linux, con logind configurado para terminar los procesos de la sesión (`KillUserProcesses=yes`), tampoco sobrevivía al cierre de la sesión. Y lo primero que hace quien se queda sin acceso es reiniciar el servidor desde la consola del proveedor: entonces los cambios se quedaban.

## Decisión
- El dead-man switch se arma como **tarea del sistema**: en Linux, una instancia de la plantilla `adarve-deadman@.service` (`WantedBy=multi-user.target`); en Windows, la tarea `\Adarve\Dead-man <cambio>`, de SYSTEM y con arranque en cada inicio del equipo. Arranca ya, fuera de la sesión del usuario, y otra vez en cada inicio hasta que se desarma.
- El plazo está en el manifiesto. Si arranca con el plazo vencido (tras un reinicio), decide en el momento: si no se confirmó, deshace los cambios de acceso remoto.
- Se desarma cuando ya no hace falta. Lo hace `harden` al confirmar o al deshacer él mismo los cambios, y el propio dead-man switch cuando no queda nada que deshacer. Si no consigue deshacerlo todo, sigue armado y lo reintenta en el siguiente arranque.
- Arranca como root o SYSTEM en cada inicio, así que solo se arma así si nadie sin privilegios puede sustituir el ejecutable (la misma comprobación que `schedule enable`). Si no se puede (sin systemd, con el ejecutable fuera de las carpetas protegidas o con `ADARVE_HOME`), se usa el proceso independiente de antes y `harden` avisa de que no sobrevivirá a un reinicio.

## Alternativas
- **Comprobar al ejecutar cualquier orden de Adarve** si hay un dead-man switch vencido. Depende de que alguien ejecute Adarve después del reinicio, y la ronda diaria puede tardar un día.
- **Una entrada `@reboot` de cron** donde no hay systemd. No todos los cron leen `/etc/cron.d` ni admiten `@reboot`, y en esos sistemas el proceso independiente ya sobrevive al cierre de la sesión.

## Consecuencias
- ✅ El dead-man switch actúa aunque se corte la sesión, se reinicie el equipo o muera `harden`.
- ✅ Lo que hace queda en `snapshots/<cambio>/deadman.log`: como tarea no tiene consola.
- ⚠️ Mientras dura el plazo hay una tarea más de root o SYSTEM: por eso exige un ejecutable protegido y se retira sola.
- ⚠️ El CI prueba el ciclo completo en Linux (`scripts/e2e/deadman-linux.sh`). En Windows prueba la tarea (arranque en el inicio, SYSTEM, con batería), pero no el ciclo con `harden`, que pide la confirmación en una consola interactiva.
