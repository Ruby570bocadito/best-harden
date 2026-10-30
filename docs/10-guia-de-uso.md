# 10 · Guía de uso

> Ejecuta Bastion como **administrador** (Windows) o con **sudo** (Linux). Sin privilegios funciona, pero algunos controles (directiva de seguridad y de auditoría, BitLocker, `/etc/shadow`, `sudoers`...) quedan **sin evaluar**, no cuentan en la puntuación y esta se marca como parcial. Los informes de `--save` se guardan entonces en tu carpeta de usuario: `%LOCALAPPDATA%\Bastion\reports` en Windows y `~/.local/share/bastion/reports` en Linux.

## Comandos

| Comando | Descripción |
|---|---|
| `bastion info [--json]` | Plataforma, rol, etiquetas, perfil por defecto, probes disponibles y rutas |
| `bastion scan` | Auditar el equipo (solo lectura) |
| `bastion surface [--all] [--format json] [-o informe.html] [--save] [--fail-on SEV] [--fail-on-new]` | Superficie de ataque: puertos expuestos con su proceso, servicios de riesgo, recursos compartidos y administradores (ver abajo) |
| `bastion surface fix [ID...] [--apply] [--include-remote]` | Limitar a la red local las reglas del Firewall de Windows que abren puertos a cualquiera, con instantánea, verificación y rollback (simulación sin `--apply`) |
| `bastion schedule [enable [--at HH:MM] \| disable \| run \| notify]` | Análisis diario programado (escaneo y superficie guardados) con el Programador de tareas o systemd, con avisos en el Visor de eventos o syslog y, si se configura, en un webhook (ntfy, Slack, Discord, Teams); sin argumentos, el estado y las últimas ejecuciones (ver abajo) |
| `bastion ui [--port N] [--no-open]` | Consola local en el navegador: postura, tendencia, plan, historial y excepciones (ver abajo) |
| `bastion profiles [--all]` | Perfiles disponibles y número de reglas |
| `bastion rules list [--all] [-p perfil]` | Reglas aplicables (o todas) |
| `bastion rules show <ID>` | Detalle, remediación, impacto y referencias de un control |
| `bastion rules lint [dir…]` | Validar el paquete oficial y reglas propias |
| `bastion rules doc` | Catálogo de controles en Markdown |
| `bastion harden [--apply] [--wave N]` | Corregir controles fallidos (simulación salvo `--apply`). Ver [05](05-remediacion-segura.md) |
| `bastion rollback [ID] [--yes]` | Deshacer un cambio de hardening (por defecto, el último) |
| `bastion history` | Cambios de hardening aplicados |
| `bastion exceptions [list\|add\|remove]` | Aceptar controles fallidos con motivo, responsable y caducidad (ver abajo) |
| `bastion update [--check] [--force] [--version vX.Y.Z]` | Actualizar Bastion y sus reglas (verificado con SHA-256), o instalar una versión concreta. En Windows pide elevación si hace falta |
| `bastion init` | Crear directorios y configuración (lo hace el instalador) |
| `bastion version [--short]` | Versión |

Opciones globales: `--no-color`, `--rules-dir <dir>` (repetible).

## `bastion scan`

| Opción | Descripción |
|---|---|
| `-p, --profile <id>` | Perfil a evaluar. Por defecto el de `config.yaml` o el que corresponde al rol del equipo |
| `-f, --format console\|json` | Formato de la salida estándar |
| `-o, --output <fichero>` | Guardar el informe en `.html` o `.json` (repetible). La extensión y la carpeta se comprueban antes de escanear; un error nunca vacía un fichero existente |
| `--save` | Guardar HTML y JSON con fecha en el directorio de informes (conserva los últimos `keep`) |
| `--open` | Abrir el informe HTML al terminar (implica `--save` si no hay `-o *.html`) |
| `-a, --all` | Mostrar también los controles superados y los que no aplican |
| `--rule <ID,…>` | Evaluar solo esas reglas |
| `--category <nombre,…>` | Evaluar solo esas categorías |
| `--min-score <n>` | Salir con código 2 si la puntuación es inferior (0-100), o si no se pudo evaluar ningún control y no hay puntuación |
| `-q, --quiet` | Sin resumen en consola |

### Ejemplos

```bash
# Auditoría estándar con informe visual
sudo bastion scan --save --open

# Perfil de alta seguridad para el portátil de un administrador
bastion scan -p win-workstation-l2 -o C:\informes\pc-admin.html

# Solo SSH y firewall
sudo bastion scan --category SSH,Firewall

# Un control concreto, con todos los resultados
sudo bastion scan --rule LNX-SSH-001 -a

# JSON para integraciones (la consola no se mezcla con el JSON)
sudo bastion scan --format json > resultado.json

# Puerta de calidad en un pipeline de imágenes
sudo bastion scan --min-score 85 -q -o informe.html || echo "La imagen no cumple"
```

### Códigos de salida

| Código | Significado |
|---|---|
| 0 | Escaneo completado (y puntuación ≥ `--min-score`, si se indicó) |
| 1 | Error (perfil inexistente, reglas inválidas, sin permisos para guardar…) |
| 2 | Puntuación inferior a `--min-score` |
| 130 | Interrumpido (Ctrl+C) |

### Cambios desde el escaneo anterior

Si hay un escaneo guardado del mismo equipo y perfil (`--save`, la consola o el análisis programado), cada escaneo se compara con él y muestra los controles que **han empeorado** (se superaban y ahora fallan: una actualización, una GPO o alguien que ha deshecho un ajuste) y los que **se han corregido**. Sale en la consola, en el informe HTML, en el Panel de `bastion ui` y en el JSON (`changes`). Los errores, los controles sin evaluar y las excepciones no cuentan como cambios.

## Corregir: `bastion harden`

```bash
sudo bastion harden                  # 1. simulación: revisa el plan
sudo bastion harden --apply          # 2. aplica la ola 1 (riesgo nulo o bajo)
sudo bastion scan --save --open      # 3. comprueba la nueva postura
sudo bastion rollback                # si algo no te convence, se deshace todo
```

Cada control se aplica con instantánea previa, se verifica y, si no se cumple o falla, se revierte solo. Olas, acceso remoto, GPO e instantáneas se explican en [05-remediacion-segura.md](05-remediacion-segura.md).

## Superficie de ataque: `bastion surface`

```bash
sudo bastion surface                  # hallazgos y puertos expuestos en la red
sudo bastion surface --all            # también lo que solo escucha en el propio equipo
bastion surface --format json > superficie.json
bastion surface --fail-on high        # código 2 si hay hallazgos altos o críticos
bastion surface -o superficie.html    # informe autocontenido para compartir o imprimir (también .json)
bastion surface --save                # guardarlo; el siguiente análisis muestra qué ha cambiado
bastion surface --save --fail-on-new  # código 3 si la exposición ha crecido (tareas programadas)
bastion surface fix                   # plan para limitar a la red local lo abierto a cualquiera
```

Agrupa los sockets por servicio (el mismo puerto en IPv4 e IPv6 es una fila) con su dirección, alcance (**red**, **local** o **cliente**), proceso y servicio conocido, y genera hallazgos para los servicios de riesgo expuestos en la red (Telnet, SMB, RDP, Redis, Docker API…), los recursos compartidos abiertos a todos y las exportaciones NFS peligrosas. Cada hallazgo dice por qué importa y cómo cerrarlo. La puntuación de exposición empieza en 100 y resta 30, 15, 7 o 3 por cada hallazgo crítico, alto, medio o bajo.

**Firewall de Windows.** En Windows, Bastion lee la política efectiva del firewall (perfiles activos, acción de entrada por defecto y reglas de entrada con sus direcciones locales y remotas e interfaces) y clasifica cada puerto como lo haría el propio firewall: en cada perfil activo, una regla de bloqueo gana a una de permiso y, sin regla, manda la acción por defecto.

Las reglas se leen del registro, donde Windows las guarda completas: el almacén local, el de directivas de grupo y el de MDM (Intune), respetando `AllowLocalPolicyMerge`. La interfaz COM, que es lo que se usa sin acceso al registro, no muestra el paquete de algunas apps de la Store ni las reglas limitadas a dispositivos de confianza o a IPsec. Por eso, sin privilegios, algún puerto puede salir abierto sin estarlo, y la salida lo advierte. El campo `firewall.source` del JSON dice de dónde salieron las reglas: `registry` o `com`.

| Estado | Significado | Hallazgo |
|---|---|---|
| **abierto** | Alguna regla lo permite desde cualquier dirección (o el firewall está desactivado) | Con su severidad |
| **limitado** | Solo lo permiten reglas restringidas: a la red local (`LocalSubnet`), a ciertas direcciones remotas, a una interfaz, a las IP de una VPN, a dispositivos Wi-Fi Direct, UPnP o cercanos ya emparejados, o a tráfico autenticado con IPsec. Por ejemplo, la regla «Tailscale-In» que crea Tailscale abre todos los puertos, pero solo para el tráfico que llega por Tailscale. Las reglas «Solo controlador de WFD» de Windows abren SMB, pero solo a dispositivos Wi-Fi Direct | Un nivel menos de severidad, diciendo desde dónde |
| **filtrado** | Ninguna regla lo permite o una de bloqueo lo impide | No |

Cada hallazgo nombra la regla que lo permite para poder comprobarlo. Las reglas de apps de la Microsoft Store (sin programa, ligadas al paquete de la app) solo se aplican a esa app. Las reglas con propietario (`LocalUserOwner`) solo cubren los procesos de ese usuario: Bastion averigua con qué cuenta corre cada proceso (`tasklist /v`) y compara el SID, así que no abren servicios del sistema como RDP o SMB. Si una de esas reglas lo permite todo, sale un hallazgo **medio**: cualquier programa del usuario puede aceptar conexiones (la app de Xbox, por ejemplo, crea reglas así). Una regla que lo permite **todo** (cualquier protocolo, puerto, programa y dirección) en un perfil activo es un hallazgo **alto** por sí misma: equivale a desactivar el firewall en esa red. Los programas instalados por el usuario (no los servicios de Windows) que tienen puertos abiertos a cualquier dirección forman un hallazgo **bajo**, con cada programa y sus puertos: es fácil olvidar que se aceptó el aviso del firewall al instalarlos.

Como las reglas se leen del almacén local del registro, Bastion conoce su nombre interno, y la solución trae el comando exacto para limitar a la red local las reglas que abren un puerto, por ejemplo `Set-NetFirewallRule -Name 'RemoteDesktop-UserMode-In-TCP' -RemoteAddress LocalSubnet` (se deshace con `-RemoteAddress Any`). Sin ese nombre (reglas de directivas de grupo o leídas con COM) se describe la regla por su nombre visible.

**Firewall de Linux.** Con root, Bastion lee el firewall del kernel: `nft -j list ruleset` para las tablas de nftables e `iptables-save`/`ip6tables-save` para las de iptables (también las de iptables-nft, que nft muestra sin el detalle de `multiport`, `conntrack` o `addrtype`). ufw y firewalld no tienen reglas propias: generan las de nftables o iptables, así que se evalúan igual, y las reglas se nombran por su comentario (los `dapp_OpenSSH` de ufw) o por su cadena y posición (`«ufw-user-input #2»`, `«input #6»`). Para cada puerto se recorren las cadenas del gancho *input* como lo haría una conexión nueva: se saltan las reglas de conexiones establecidas, de la interfaz `lo` y de difusión o multidifusión; los saltos (`jump`, `goto`) se siguen; una regla limitada a ciertos orígenes, a una interfaz (`tailscale0` cuenta como Tailscale) o a ciertos destinos deja el puerto **limitado**; y un bloqueo con condiciones que no se pueden evaluar no cuenta, para no dar nunca por filtrado lo que podría estar abierto. Los puertos que publica Docker (`docker-proxy`) se consideran abiertos: entran con DNAT y no pasan por la cadena *input*. Sin root no se puede leer el firewall y la salida lo advierte.

**Cambios entre análisis.** Con `--save`, el análisis se guarda (HTML y JSON, con el prefijo `surface-` junto a los informes de escaneo y la misma retención). Desde entonces, cada `bastion surface`, y la pestaña Superficie de la consola, se compara con el último guardado del equipo y muestra qué ha cambiado:

- servicios que empiezan a escuchar en la red (`+`) o que dejan de hacerlo (`-`);
- puertos que el firewall deja más abiertos (`↑`, por ejemplo de «limitado» a «abierto») o más cerrados (`↓`);
- hallazgos nuevos (`!`) y resueltos (`✓`), y la exposición de antes y de ahora.

Lo que aumenta la exposición sale primero. Es la forma de enterarse de que un programa recién instalado ha abierto un puerto o de que alguien ha cambiado una regla. En una tarea programada, `bastion surface --save --fail-on-new` sale con código 3 si la exposición ha crecido. El JSON incluye la comparación en `changes`.

**Corregir: `bastion surface fix`.** En Windows, los hallazgos de puertos abiertos a cualquiera por reglas del almacén local (RDP, mDNS, programas…) se pueden corregir sin copiar comandos: `bastion surface fix` muestra el plan, una línea por regla con su protocolo y puertos, sus direcciones remotas actuales y `LocalSubnet` como destino (una regla que abre puertos de dos hallazgos se limita una vez, con el más grave), y `--apply` lo aplica como `harden`. Primero guarda una instantánea; luego limita cada regla, vuelve a leerla para verificar y, si no quedó limitada, la revierte. El cambio aparece en `bastion history` y en la consola, y se deshace con `bastion rollback`. Se puede limitar a ciertos hallazgos (`bastion surface fix SURF-APPS-OPEN --apply`). RDP (también su regla UDP), SSH, WinRM, VNC y Sunshine solo se incluyen con `--include-remote` y se aplican con *dead-man switch*. Lo que llega por otras reglas ya limitadas, como la de Tailscale, sigue llegando.

Los sockets UDP en puertos dinámicos (49152-65535 en Windows; `ip_local_port_range` en Linux) son de clientes, como las consultas DNS: se muestran como **cliente** solo con `--all` y no cuentan como servicios. Los puertos TCP dinámicos de `lsass`, `services`, `spoolsv`… se etiquetan como **RPC dinámico**. NetBIOS (137-139) cuenta como un único hallazgo, y Sunshine/GameStream (47984-48010, con su panel web en 47990) también: es un escritorio remoto, así que abierto a cualquiera es un hallazgo medio y `surface fix` solo lo limita con `--include-remote`. SSH solo es un hallazgo (bajo) en estaciones de trabajo: en un servidor es lo normal. Los puertos habituales que no son un riesgo por sí mismos solo se etiquetan, sin hallazgo: WSD (5357), dispositivos conectados (5040), optimización de distribución (7680), IKE (500/4500) o las VPN que solo responden a pares autenticados (Tailscale en 41641, WireGuard en 51820, ZeroTier en 9993), entre otros. Los de un programa, como Steam Remote Play (27036), cuentan entre los programas abiertos a cualquiera si el firewall no los limita. Si en un puerto del catálogo lo que queda abierto no es el servicio de Windows sino un programa (uno que abre el de SSDP, por ejemplo), la solución habla del programa.

**De dónde viene cada programa.** Para cada proceso que escucha en la red, Bastion comprueba su origen. En Windows, la firma Authenticode del ejecutable (incrustada o de catálogo, como casi todo Windows): los programas **sin firma digital** que aceptan conexiones desde la red forman un hallazgo bajo (`SURF-UNSIGNED`; no siempre es malo: muchas herramientas, juegos y programas hechos con Python o Node no se firman), y una firma que **no vale** es un hallazgo propio: alto si el fichero se ha modificado después de firmarlo, medio si el certificado no es de confianza (`SURF-BADSIG`). En Linux, el paquete que instala el ejecutable (dpkg, rpm, pacman o snap): lo que no es de ningún paquete no recibe las actualizaciones del sistema (`SURF-UNPACKAGED`, bajo), y un ejecutable cuyo contenido ya no coincide con la suma que registró su paquete (`dpkg --verify` o `rpm -V`) es un hallazgo alto (`SURF-BADSIG`): puede ser un parche propio, pero también un binario sustituido. Los procesos de contenedores no se comprueban (su ruta no es la del sistema). La tabla de servicios marca lo que conviene revisar, y el informe HTML y la consola muestran el firmante o el paquete de cada proceso.

Ejecútalo como administrador o root: sin privilegios no se ve el proceso de otros usuarios y, en Windows, no se leen los recursos compartidos.

| Opción | Descripción |
|---|---|
| `-a, --all` | Incluir los servicios que solo escuchan en `127.0.0.1`/`::1` |
| `-f, --format console\|json` | Formato de la salida (`bastion.surface/v1`) |
| `-o fichero.json` | Guardar el análisis |
| `--fail-on critical\|high\|medium\|low` | Código de salida 2 si hay hallazgos de esa severidad o mayor |

## Análisis programado: `bastion schedule`

```bash
sudo bastion schedule enable            # cada día a las 09:00 (Windows: como administrador, sin sudo)
sudo bastion schedule enable --at 13:30
bastion schedule                        # estado y últimas ejecuciones
sudo bastion schedule notify --set https://ntfy.sh/<tema>   # avisos en el móvil o en un chat
sudo bastion schedule disable           # quita la tarea; los informes se conservan
```

Crea una tarea en el planificador del sistema: el Programador de tareas en Windows (`\Bastion\Escaneo diario`, como SYSTEM) y un temporizador de systemd en Linux (`bastion-scan.timer`), o una entrada en `/etc/cron.d/bastion` si no hay systemd. Si el equipo está apagado a esa hora, se hace al encenderlo; en portátiles también se ejecuta con batería. La hora es local y no se desplaza con el horario de verano.

Cada ejecución (`bastion schedule run`) guarda un escaneo y un análisis de superficie comparado con el anterior y lo anota en `schedule.log`, en la carpeta de datos. Así `bastion ui` dibuja la tendencia de la postura, y `bastion surface` y la pestaña Superficie avisan de lo que ha cambiado. Si algún control ha empeorado o la exposición ha crecido, la tarea termina con código 3 (en Windows aparece como último resultado de la tarea) y `bastion schedule` lo muestra en sus últimas ejecuciones.

**Avisos.** Cada ejecución queda en el registro del sistema: en Windows, en el Visor de eventos (*Registros de Windows › Aplicación*, origen **Bastion**: evento 100 si no hay cambios a peor, 200 —advertencia— si la postura o la exposición han empeorado y 300 —error— si el análisis ha fallado); en Linux, en syslog (`journalctl -t bastion`). Un SIEM o un reenvío de eventos lo recogen sin más. Para enterarte sin mirar, añade un webhook:

```bash
sudo bastion schedule notify --set https://ntfy.sh/bastion-casa-7f3k9   # ntfy: notificaciones en el móvil, sin cuenta
sudo bastion schedule notify --set https://hooks.slack.com/services/…   # Slack (también Discord y Teams)
sudo bastion schedule notify --set https://… --when always               # avisar también sin cambios a peor
sudo bastion schedule notify                                             # enviar un aviso de prueba
sudo bastion schedule notify --clear
```

La dirección suele llevar un secreto: con `--set -` se lee de la entrada estándar (`sudo bastion schedule notify --set - < webhook.txt`) y no queda en el historial de la shell ni en la lista de procesos. `--set` envía primero un aviso de prueba y solo guarda la dirección (en la sección `notify` de `config.yaml`) si llega. El formato se deduce de la dirección (ntfy, Slack, Discord, Teams —flujos de *Workflows* o conectores de webhook entrante— y, para cualquier otra, JSON con el esquema `bastion.notify/v1`); `--format` lo fuerza. Por defecto solo se avisa al webhook cuando algo empeora o falla. El aviso lleva el equipo, las puntuaciones y los títulos de los cambios, nunca evidencias. Con ntfy, el tema funciona como contraseña: elige uno difícil de adivinar. Si un aviso no llega, `bastion schedule` lo indica en sus últimas ejecuciones.

Como la tarea se ejecuta como SYSTEM o root, `enable` se niega si el ejecutable está en una carpeta que otros usuarios pueden modificar (Descargas, el escritorio, una carpeta de `/home`…): quien pudiera sustituirlo obtendría esos privilegios. El instalador deja Bastion en `Program Files` o `/usr/local/bin`, que son seguras. `--unsafe-path` lo permite igualmente, solo para laboratorios.

## Consola local: `bastion ui`

```bash
sudo bastion ui                      # abre el navegador con la consola
bastion ui --port 8790 --no-open     # puerto fijo, sin abrir el navegador
```

Muestra la dirección (`http://127.0.0.1:<puerto>/?t=<token>`) y queda en marcha hasta Ctrl+C. Al abrir esa dirección, la consola fija una cookie de sesión (HttpOnly, SameSite=Strict) y redirige a `/`, así que el token no se queda en la barra de direcciones. El navegador se abre con un fichero local privado que redirige con un código de un solo uso: el token no aparece en la línea de órdenes del navegador, que otros usuarios del equipo pueden ver. Para scripts, la API acepta el token en la cabecera `X-Bastion-Token`. Un escaneo lanzado desde la consola termina aunque cierres la pestaña, y uno interrumpido (Ctrl+C) no se guarda. Al abrirla escanea si el último escaneo tiene más de una hora; cada escaneo se guarda en el directorio de informes y alimenta la tendencia y el historial. Las pestañas se describen en [07-ui-y-diseno.md](07-ui-y-diseno.md#consola-local-bastion-ui-).

La consola **solo lee y escanea**: el plan de hardening es una simulación y los cambios se aplican desde la terminal con `bastion harden --apply`. Solo escucha en `127.0.0.1` y exige el token de la dirección, así que ni otra web ni otro usuario del equipo pueden usarla ([ADR-0008](adr/0008-consola-local.md)).

**Servidor sin escritorio:** fija el puerto y abre un túnel SSH desde tu equipo.

```bash
sudo bastion ui --port 8790 --no-open          # en el servidor
ssh -L 8790:127.0.0.1:8790 usuario@servidor    # en tu equipo; abre la dirección que mostró el servidor
```

## Aceptar un riesgo: `bastion exceptions`

Cuando un control falla y hay un buen motivo para no corregirlo (un control compensatorio, hardware antiguo, un proveedor que lo exige), regístralo como excepción en lugar de ignorarlo:

```bash
sudo bastion exceptions add WIN-SYS-003 --reason "Equipo sin UEFI; se sustituye en enero" --expires 2027-01-31
sudo bastion exceptions add LNX-FW-001 --reason "Filtrado en el cortafuegos perimetral FW-02" --expires 90d
sudo bastion exceptions add WIN-RDP-001 --reason "Cliente RDP heredado del proveedor" --expires 6m --host SRV-ERP01
bastion exceptions list           # vigencia de cada una (en amarillo si caduca en menos de 30 días)
sudo bastion exceptions remove LNX-FW-001
```

| Opción | Descripción |
|---|---|
| `-r, --reason` | Motivo (obligatorio, una línea de al menos 10 caracteres) |
| `-e, --expires` | Caducidad obligatoria: fecha `AAAA-MM-DD` o plazo `90d`, `12w`, `6m`, `1y`. Como mucho un año |
| `--owner` | Responsable (por defecto, el usuario actual) |
| `--host` | Limitar a estos equipos (repetible) |

`add` sobre una regla que ya tiene excepción la **renueva**. El control con excepción vigente sale como ◇ **excepción**: no cuenta en la puntuación y `harden` no lo modifica. Al caducar vuelve a fallar y Bastion lo avisa en cada escaneo.

Se guardan en `exceptions.yaml`, junto a `config.yaml` (`/etc/bastion` o `%ProgramData%\Bastion`):

```yaml
schema: bastion.exceptions/v1
exceptions:
  - rule: LNX-FW-001
    reason: Filtrado en el cortafuegos perimetral FW-02
    owner: seguridad
    created: "2026-10-15"
    expires: "2027-01-13"
```

Si editas el fichero a mano, Bastion ignora las excepciones inválidas (sin motivo, sin caducidad o con más de un año de vigencia) y lo avisa.

## Interpretar los resultados

| Estado | Significado | ¿Cuenta en la puntuación? |
|---|---|---|
| ✓ **Superado** | El valor real cumple lo esperado | Sí |
| ✗ **Fallido** | El valor real no cumple (o no está configurado y el valor por defecto del sistema no cumple) | Sí |
| ! **Error** | No se pudo leer por un problema inesperado (comando que falla, formato desconocido…) | No; la puntuación se marca como **parcial** |
| ◇ **Excepción** | Falla, pero hay una excepción vigente que lo acepta | No; se muestra aparte y con su caducidad |
| ⊘ **Sin evaluar** | El dato solo se puede leer como administrador o root y el escaneo se ejecutó sin privilegios. En consola se resumen en una línea; `--all` los lista | No; la puntuación se marca como **parcial** |
| – **No aplica** | El elemento no existe en este equipo (sin OpenSSH, sin systemd, Defender sustituido por otro antivirus…) | No |

Cuando el informe dice `actual 1 (por defecto)`, el valor no estaba configurado explícitamente y Bastion aplicó el valor por defecto documentado del sistema operativo.

## Formato JSON (`bastion.report/v1`)

```json
{
  "schema": "bastion.report/v1",
  "tool": { "name": "bastion", "version": "0.1.0", "commit": "abc1234" },
  "host": { "hostname": "web-01", "os": "linux", "name": "Ubuntu 24.04.1 LTS", "role": "server",
            "tags": ["linux-ubuntu", "linux-debian", "linux"], "is_admin": true },
  "profile": { "id": "linux-server-l1", "name": "Linux Servidor · Nivel 1" },
  "started_at": "2026-10-15T14:35:00Z", "finished_at": "…", "duration_ms": 39,
  "score": { "value": 65, "grade": "D", "partial": false, "total": 57, "passed": 22, "failed": 15,
             "errors": 0, "skipped": 0, "exceptions": 0, "na": 20, "by_severity": { "high": { "failed": 2 } }, "by_category": [ … ] },
  "results": [
    { "rule": { "id": "LNX-FW-001", "title": "…", "severity": "high", "category": "Firewall",
                "references": { … }, "remediation": { … } },
      "status": "fail", "actual": "…", "expected": "…", "source": "…",
      "children": [ { "status": "fail", "label": "ufw", "actual": "no configurado", "expected": "yes",
                      "source": "/etc/ufw/ufw.conf" } ] }
  ]
}
```

Si hay un escaneo anterior guardado del mismo perfil, el informe incluye además `"changes": {"since": "…", "score_before": 80, "regressions": [ … ], "fixed": [ … ]}` con los controles que han empeorado y los que se han corregido.

El formato es estable dentro de `v1`: solo se añadirán campos, nunca se eliminarán ni cambiarán de significado.

## Configuración (`config.yaml`)

```yaml
profile: auto                 # o un perfil concreto
reports:
  dir: /var/lib/bastion/reports
  keep: 30                    # escaneos que se conservan con --save
rules:
  extra_dirs:
    - /etc/bastion/rules.d    # reglas propias (*.yaml)
update:
  # repo: mi-org/bastion
  # releases_url: https://mirror.interno/bastion
```

## Reglas propias

1. Crea un `.yaml` en `rules.d` siguiendo [04-motor-de-reglas.md](04-motor-de-reglas.md). Usa un prefijo propio en el ID (p. ej. `ACME-WEB-001`) y asígnalo a un perfil existente.
2. Valídalo: `bastion rules lint /etc/bastion/rules.d`.
3. Ejecuta `bastion scan`: las reglas propias se evalúan junto a las oficiales.
