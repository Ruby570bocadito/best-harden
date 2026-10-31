# 08 · Seguridad de la plataforma

Adarve se ejecuta como **SYSTEM/root** en equipos críticos. Para un atacante es un objetivo muy valioso: si lo compromete, controla toda la flota. Por eso la seguridad de la propia herramienta forma parte del diseño desde el primer día.

## Modelo de amenazas (resumen)

| Amenaza | Vector | Control |
|---|---|---|
| Adarve como herramienta de ejecución remota (C2) | Servidor comprometido que envía comandos | **No existe** la capacidad de ejecutar comandos arbitrarios ([ADR-0004](adr/0004-sin-ejecucion-arbitraria.md)) |
| Paquete de reglas malicioso | Regla que intenta ejecutar código | Reglas declarativas; los probes usan comandos fijos; `ps` solo admite una lista blanca |
| Secuestro de binarios | `PATH` manipulado para suplantar `secedit` o `powershell` | Rutas absolutas `%SystemRoot%\System32\...` en Windows |
| Actualización manipulada | Mirror comprometido o MITM | HTTPS obligatorio (también en las redirecciones; `http://` solo hacia el propio equipo) + verificación SHA-256; con privilegios se ignoran `ADARVE_RELEASES_URL`/`ADARVE_REPO`/`ADARVE_HOME` salvo con `--trust-env`; atestación de procedencia SLSA verificable con `gh attestation verify` (🔜 verificación en el propio `update`) |
| XSS en el informe | Valor hostil leído del sistema (p. ej. una línea de `sudoers`) | JSON escapado, `textContent`, CSP con nonce |
| Lectura de datos sensibles | Informes y configuración legibles por cualquiera | Directorios con permisos restringidos a root / Administradores+SYSTEM |
| Configuración plantada | Otro usuario crea `%ProgramData%Adarve` o `config.yaml` antes que el administrador | Con privilegios se comprueban propietario y DACL (o modo) de la carpeta, `config.yaml`, `exceptions.yaml` y `rules.d`; si no son solo de administradores se ignoran, y los comandos que escriben los apartan (`*.no-confiable-<fecha>`) y restablecen los permisos |
| Secuencias de escape en la terminal | Un proceso con un nombre con ESC u OSC 52 | La salida de consola quita los caracteres de control de los datos del sistema auditado |
| Denegación de servicio del escaneo | Fichero enorme o probe colgado | Límite de 4 MiB por fichero, timeout de 60 s por comando, `recover` por regla |

## Controles implementados (✅)

### Sin ejecución arbitraria
- Las reglas son YAML declarativo. Los parámetros de un probe nunca se interpolan en comandos.
- Comandos usados por los probes: `secedit /export`, `auditpol /backup`, `powershell.exe -NoProfile -NonInteractive -Command <consulta fija>`, `sshd -T`, `systemctl show`, `dpkg-query`, `rpm -q`. Todos son de **solo lectura**.
- Las consultas PowerShell no usan `-EncodedCommand` ni `-ExecutionPolicy Bypass`, para no parecerse a malware ni generar ruido en el EDR. Quedan en el ScriptBlock Logging de forma legible.
- Cuando una consulta necesita datos (las rutas de los programas cuya firma comprueba `adarve surface`, el nombre de una regla del firewall en `surface fix`), le llegan por variables de entorno y el script fijo los lee de `$env`: nunca forman parte de su texto, así que una ruta o un nombre manipulados no pueden inyectar código.

### Cambios controlados (`harden`)
- Solo **acciones tipadas** (13 tipos). Ninguna ejecuta comandos libres: los cmdlets de Defender reciben GUIDs, enteros o nombres de una lista blanca, ya validados.
- Los parámetros se validan con listas blancas y expresiones regulares, también en `rules lint`: solo HKLM, claves `secedit` permitidas, rutas `/etc` sin `..`, nada de saltos de línea que inyecten directivas en `sshd_config` o `sudoers`.
- **Registro previo**: el estado anterior se escribe en el manifiesto antes de aplicar; un fallo a mitad sigue siendo reversible.
- `sshd -t` y `visudo -c` validan antes de dejar un cambio en SSH o sudoers; si falla, se restaura de inmediato.
- Dead-man switch en un proceso independiente para los cambios de acceso remoto.

### Solo lectura en `scan`
- `adarve scan` no modifica el sistema. Los únicos ficheros que escribe son los informes que se piden y ficheros temporales privados (`secpol.inf`, `audit.csv`), que se borran al terminar.

### Actualizaciones verificadas
- El instalador y `adarve update` descargan `checksums.txt` y verifican el SHA-256 del archivo **antes** de extraerlo. Si no coincide, abortan sin tocar la instalación existente.
- Reemplazo atómico en Linux (`rename`) y renombrado seguro en Windows (`.old`).
- Límites de tamaño en descargas y extracción.

### Informe HTML
- Los datos se serializan con `encoding/json`, que escapa `<`, `>` y `&`, así que no pueden cerrar la etiqueta `<script>`.
- El JavaScript inserta todo con `textContent` y nunca con `innerHTML`.
- **CSP**: `default-src 'none'; script-src 'nonce-<aleatorio>'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'`. Aunque se inyectara HTML, ningún script sin el nonce se ejecutaría y no se puede cargar nada externo.
- Los enlaces externos (MITRE) usan `rel="noopener noreferrer"`.

### Consola local (`adarve ui`)
- Escucha solo en `127.0.0.1` y toda la API exige un token aleatorio de 256 bits por sesión (cabecera `X-Adarve-Token`, o cookie de sesión HttpOnly y SameSite=Strict más la cabecera `X-Adarve-Request`; comparación en tiempo constante). El token solo se muestra en la terminal: el navegador se abre con un fichero local 0600 que redirige con un código de un solo uso, así que no aparece en la línea de órdenes del navegador (visible en `/proc`) ni en las URLs de la consola.
- Rechaza cualquier `Host` que no sea de loopback (**DNS rebinding**) y las peticiones de escritura con un `Origin` ajeno; no responde a CORS, así que una web maliciosa no puede enviar el token ni leer respuestas (**CSRF**).
- CSP con nonce y `frame-ancestors 'none'`, `nosniff`, `no-referrer`, `no-store`, COOP/CORP; datos insertados con `textContent`.
- Solo lee y escanea: aplicar o deshacer cambios y editar excepciones sigue exigiendo la terminal. Detalle en [ADR-0008](adr/0008-consola-local.md).

### Análisis programado (`schedule`)
- La tarea diaria se ejecuta como SYSTEM o root. `schedule enable` se niega si el ejecutable está en una carpeta que puede modificar un usuario sin privilegios: en Windows debe estar en Program Files (la carpeta de Windows no vale: tiene subcarpetas con escritura para todos, como Temp); en Linux, el fichero y todas las carpetas hasta `/` deben ser de root y sin escritura para el grupo ni otros.
- La ruta del ejecutable y la hora llegan a PowerShell por variables de entorno, nunca dentro del script; la hora se valida antes (HH:MM).
- La tarea solo hace lo que haría `adarve scan --save` y `adarve surface --save`: no aplica cambios.
- **Avisos por webhook** (opcional, desactivados por defecto). Es la única conexión de salida de Adarve además de `adarve update`. Solo HTTPS (HTTP únicamente hacia el propio equipo o una IP privada); sin seguir redirecciones, que convertirían el POST en una petición a otro sitio; con 20 s de límite. El aviso lleva el resumen (equipo, puntuaciones, títulos de los cambios), nunca evidencias ni configuración. La dirección suele incluir el secreto (el tema de ntfy, el token de Slack): se guarda en `config.yaml`, que solo leen Administradores y SYSTEM (o root), y Adarve solo muestra el esquema y el servidor, también en los errores. `--set` no guarda la dirección hasta que el aviso de prueba llega.

### Permisos
- Linux: `/etc/adarve` y `/var/lib/adarve` con `0750` (root). Informes con `0640`.
- Windows: `%ProgramData%\Adarve` sin herencia, acceso total solo para Administradores (`S-1-5-32-544`) y SYSTEM (`S-1-5-18`), por SID para que funcione en cualquier idioma. El directorio `reports` concede además **lectura** al usuario que ejecutó el escaneo: con UAC, su navegador corre sin elevar y no podría abrir el informe.
- **Carpeta preparada por un atacante.** Cualquier usuario puede crear carpetas en `%ProgramData%`. Si alguien creara `C:\ProgramData\Adarve` antes de instalar, seguiría siendo su propietario (y el propietario siempre puede cambiar los permisos) y podría dejar un `config.yaml` que apuntara `adarve update` a un espejo suyo. Por eso `adarve init` (lo ejecuta el instalador) pasa la propiedad de todo a Administradores, quita la herencia de la carpeta y restablece los permisos de su contenido para que solo hereden los de la carpeta. En Linux, `/etc/adarve` y `/var/lib/adarve` pasan a `root:root`.
- Sin privilegios, Adarve no intenta escribir en esas carpetas: los informes van a la carpeta del usuario y `config.yaml` (que no puede leer) se sustituye por los valores por defecto.
- Las reglas propias (`rules.d`) y las excepciones (`exceptions.yaml`) solo las puede escribir un administrador. Una excepción nunca es permanente: caduca como mucho al año.

### Desarrollo seguro
- CI con `go vet` y tests en Linux y Windows (con detector de carreras en Linux), ShellCheck y PSScriptAnalyzer.
- Releases reproducibles con GoReleaser y SBOM (Syft).
- Atestación de procedencia SLSA de cada archivo publicado (`actions/attest-build-provenance`), firmada con la identidad OIDC del workflow en Sigstore: prueba qué workflow, commit y etiqueta lo construyeron.
- Sin CGO: binario estático con la mínima superficie.

## Controles planificados (🔜)

| Fase | Control |
|---|---|
| 1 | Verificar la atestación de procedencia en el instalador y en `update` (hoy se verifica a mano con `gh attestation verify`) |
| 1 | Authenticode para `adarve.exe` (evita SmartScreen y mejora la confianza del EDR) |
| 2 | Paquetes de reglas firmados; lista de claves de confianza para reglas propias |
| 2 | Instantáneas con hash y ACL; log local de cambios encadenado por hash |
| 3 | mTLS agente-servidor, alta con token de un solo uso y rotación de certificados |
| 3 | El agente no abre puertos; la UI local solo en `127.0.0.1` con token |
| 3 | RBAC, SSO/OIDC, MFA y aprobación a cuatro ojos para cambios en producción |
| 3 | Log de auditoría del servidor encadenado por hash |
| 4 | `lockdown` con MFA, motivo obligatorio y TTL |
| — | *Dogfooding*: Adarve endurece y vigila su propio servidor |

## Reporte de vulnerabilidades

Ver [SECURITY.md](../SECURITY.md).
