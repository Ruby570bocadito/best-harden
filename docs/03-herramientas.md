# 03 · Suite de herramientas

Adarve es una **suite de 16 herramientas sobre el mismo motor y el mismo agente**, organizadas en el ciclo de la seguridad defensiva:

```
              ┌─────────────────── 1. EVALUAR ───────────────────┐
              │  scan · surface · ad · vuln                       │
              └──────────────────────────┬────────────────────────┘
                                         ▼
 ┌──── 4. GOBERNAR ────┐   ┌─────────────── 2. ENDURECER ───────────────┐
 │ report · exceptions │◄──│  observe · plan · harden · studio           │
 │ rule SDK · API      │   └──────────────────────┬──────────────────────┘
 └──────────▲──────────┘                          ▼
            │              ┌─────────────── 3. DEFENDER ────────────────┐
            └──────────────│  guard · telemetry · hunt · lockdown        │
                           └─────────────────────────────────────────────┘
```

| Herramienta | Familia | Estado | Fase |
|---|---|---|---|
| `scan` | Evaluar | ✅ | 1 |
| `report` | Gobernar | ✅ consola, JSON y HTML · 🔜 PDF por marco | 1 / 5 |
| `ui` | Gobernar | ✅ consola local: tendencia, plan, historial y excepciones | 1 |
| `rule` (SDK) | Gobernar | ✅ `list`, `show`, `lint`, `doc` · 🔜 `new`, `test`, `pack` | 1 / 2 |
| `update` | — | ✅ | 0 |
| `surface` | Evaluar | ✅ puertos, servicios de riesgo, recursos compartidos, administradores y Firewall de Windows · 🔜 firewall de Linux, firma de binarios y grafo | 1 |
| `harden` | Endurecer | ✅ simulación, instantánea, verificación, rollback, dead-man switch · 🔜 *health checks* | 2 |
| `plan` | Endurecer | ✅ olas por riesgo de rotura (en `harden`) · 🔜 prioridad por exposición y anillos | 2 / 5 |
| `studio` | Endurecer | 🔜 | 2 |
| `observe` | Endurecer | 🔜 | 3 |
| `guard` | Defender | 🔜 | 3 |
| `exceptions` | Gobernar | ✅ locales con motivo, responsable y caducidad · 🔜 flujo de aprobación en la consola | 1 / 3 |
| API e integraciones | Gobernar | 🔜 | 3 |
| `telemetry` | Defender | 🔜 | 4 |
| `hunt` | Defender | 🔜 | 4 |
| `lockdown` | Defender | 🔜 | 4 |
| `vuln` | Evaluar | 🔜 | 4 |
| `ad` | Evaluar | 🔜 | 5 |

---

# 1. EVALUAR

## `adarve scan`: auditor de cumplimiento ✅

**Qué resuelve:** responde a "¿cómo de seguro está este equipo según CIS, STIG o mi política?" con evidencias.

- **Detección automática** de edición, build, rol (estación, servidor miembro, DC), unión a dominio y distro, para elegir solo las reglas aplicables.
- **Valor efectivo**: `sshd -T`, sysctl en ejecución, firewall en *ActiveStore*, `auditpol /backup`.
- **Evidencia por control**: valor actual, valor esperado, origen del dato y subcomprobaciones.
- **Estados**: `pass` · `fail` · `error` · `skipped` (requiere privilegios) · `exception` (riesgo aceptado) · `na` (🔜 `manual`).
- **Rápido**: probes en paralelo con caché por escaneo (57 controles en unos 40 ms en Linux).
- **Portable**: un único binario sin instalación; ideal en un USB para consultores.
- 🔜 Detectar **quién gestiona el valor** (GPO de dominio, Intune/MDM o local).

Referencia de opciones: [10-guia-de-uso.md](10-guia-de-uso.md).

## `adarve surface`: superficie de ataque ✅ / 🔜

**Qué resuelve:** responde a "¿qué puede tocar un atacante desde la red?".

```bash
sudo adarve surface                  # hallazgos y puertos expuestos en la red
sudo adarve surface --all            # también lo que solo escucha en localhost
adarve surface --format json         # adarve.surface/v1
adarve surface --fail-on high        # código 2 si hay hallazgos altos o críticos (CI/CD)
```

Implementado (v1):

- ✅ **Servicios a la escucha** con dirección, alcance (red o solo local), proceso y PID, y en Windows los servicios que comparten el proceso (`svchost.exe · TermService`). Linux: `/proc/net` y `/proc/<pid>/fd`, sin ejecutar nada. Windows: `netstat -ano` y `tasklist /svc` con ruta absoluta, interpretados sin depender del idioma.
- ✅ **Catálogo de unos 40 servicios** cuyo riesgo depende de estar expuestos (Telnet, rsh, FTP, TFTP, SNMP, SMB, NetBIOS, RDP, VNC, Sunshine, WinRM, Redis, MongoDB, Elasticsearch, memcached, Docker API, etcd, kubelet, bases de datos…), cada uno con el motivo y cómo cerrarlo. El mismo puerto en IPv4 e IPv6 cuenta una vez.
- ✅ **Recursos compartidos:** SMB con lectura o escritura para Todos, Anónimo, Usuarios autenticados o Invitados (por SID, sin depender del idioma); exportaciones NFS con `no_root_squash` o para cualquier cliente; recursos Samba con acceso de invitado.
- ✅ **Administradores:** miembros del grupo Administradores (S-1-5-32-544) en Windows; cuentas con UID 0 y miembros de `sudo`, `wheel` y `admin` en Linux.
- ✅ **Firewall de Windows:** con la política efectiva (perfiles activos, acción por defecto y reglas de entrada leídas del registro, con sus direcciones, interfaces, dispositivos de confianza, IPsec y paquete de la app; sin privilegios, con `HNetCfg.FwPolicy2`) cada puerto se marca como **abierto** (a cualquiera), **limitado** (solo red local, una VPN como Tailscale, ciertas direcciones o interfaces) o **filtrado**, con la regla que lo explica. Lo limitado baja un nivel de severidad; lo filtrado no genera hallazgos.
- ✅ **Firewall de Linux:** con root, nftables (`nft -j list ruleset`) e iptables (`iptables-save`), lo que cubre ufw, firewalld y Docker; mismos estados abierto, limitado y filtrado.
- ✅ Origen de cada programa que escucha en la red: firma Authenticode (incrustada o de catálogo) en Windows y paquete (dpkg, rpm, pacman, snap) en Linux; hallazgos para los que no tienen firma o paquete y, más graves, para las firmas que no valen.
- ✅ Sockets UDP de cliente (puertos dinámicos) separados de los servicios, IPv4 e IPv6 en una fila, RPC dinámico de Windows etiquetado y NetBIOS como un único hallazgo.
- ✅ **Puntuación de exposición** de 0 a 100 (crítico −30, alto −15, medio −7, bajo −3) y pestaña **Superficie** en `adarve ui`.

Objetivo completo:

| Área | Qué analiza |
|---|---|
| Puertos realmente expuestos | Cruza los puertos a la escucha con proceso, binario y firma, el bind (0.0.0.0 o localhost) y las reglas del firewall |
| Protocolos heredados o envenenables | LLMNR, NBT-NS, mDNS, WPAD, SMBv1, NTLMv1/LM, TLS 1.0/1.1, RC4/3DES, Telnet, FTP, rsh |
| Acceso remoto | RDP, WinRM, SSH, VNC y software de acceso remoto no autorizado |
| Recursos compartidos | Shares con escritura para Everyone o Authenticated Users, exports NFS |
| Cuentas | Administradores locales, Guest, contraseñas que no expiran, cuentas inactivas, UID 0 duplicado |
| Servicios por rol | Spooler en servidores, Remote Registry, avahi, cups, rpcbind… |

🔜 Evaluar ufw, firewalld y nftables en Linux, comprobar la firma del binario de cada proceso y mostrarlo como un grafo de exposición (host → puerto → servicio → riesgo).

## `adarve ad`: auditor de Active Directory 🔜

Lectura LDAP con una **cuenta de dominio normal** (no requiere Domain Admin).

| Categoría | Comprobaciones |
|---|---|
| Kerberos | Cuentas con SPN y RC4 (kerberoastables), cuentas sin preautenticación (AS-REP), krbtgt sin rotar en más de 180 días, DES/RC4 permitidos |
| Delegación | Sin restricciones fuera de los DCs, protocol transition, RBCD sospechoso |
| Privilegios | Grupos privilegiados, Protected Users, `adminCount` huérfanos, **DCSync fuera de los DCs**, ACL peligrosas en AdminSDHolder, GPOs y OUs |
| Contraseñas | `cpassword` (GPP) en SYSVOL, `PASSWD_NOTREQD`, admins con contraseña que nunca expira, FGPP, cobertura de LAPS |
| DCs | Spooler, firma LDAP y channel binding, firma SMB, sistema operativo obsoleto, nivel funcional |
| Higiene | Cuentas y equipos inactivos, `MachineAccountQuota > 0`, trusts sin SID filtering |
| AD CS (opcional) | Plantillas vulnerables ESC1–ESC8 y siguientes (solo detección) |

## `adarve vuln`: parches y vulnerabilidades 🔜

- Inventario de software: Uninstall, MSI y Appx en Windows; dpkg, rpm, snap y flatpak en Linux.
- Parches: build y UBR frente a la última actualización acumulativa (MSRC CVRF); actualizaciones de seguridad pendientes de apt y dnf.
- Cruce con OSV.dev, NVD y MSRC; priorización con **CISA KEV** y **EPSS**.
- Sistemas fuera de soporte (Windows 10 sin ESU, Server 2012 R2, CentOS 7…).
- Base de datos descargable para redes aisladas.

---

# 2. ENDURECER

## `adarve observe`: auditar primero, aplicar después 🔜

**Es la función estrella.** Antes de aplicar controles que suelen romper cosas, Adarve **activa la auditoría nativa durante N días** y recoge quién usa cada cosa.

| Control | Auditoría que activa | Evidencia |
|---|---|---|
| Deshabilitar SMBv1 | `AuditSmb1Access` | Evento 3000 (SMBServer/Audit) con IP del cliente |
| Restringir NTLM | *Restrict NTLM: Audit* | Eventos 8001–8004 (NTLM/Operational) |
| Exigir firma LDAP | *LDAP Interface Events* = 2 | Evento 2889 en los DCs |
| Kerberos sin RC4 | — | Evento 4769 con tipo `0x17` |
| Reglas ASR | Modo *Audit* | Evento 1122 de Defender |
| AppLocker / WDAC | Modo auditoría | AppLocker 8003/8006 · CodeIntegrity 3076 |
| TLS 1.0/1.1 off | Campos TLS de IIS / Schannel | Clientes y versión negociada |
| SELinux enforcing | Modo *permissive* | Denegaciones AVC |
| Firewall Linux | Regla de log en nftables | Flujos reales |

```
 ✅ SMBv1         0 clientes en 14 días            → LISTO PARA APLICAR
 ⚠️ NTLM          3 clientes: 10.0.4.12, ERP-APP01, svc_scan → requiere acción previa
```

## `adarve plan`: priorizador y planificador 🚧 (olas ✅)

- **Riesgo** = severidad × exposición × explotabilidad (ATT&CK/KEV) × criticidad del activo.
- **Coste** = riesgo de rotura (dato de `observe` y `breaking_risk` de la regla) + reinicio + esfuerzo.
- **Olas**: 1) cambios rápidos sin riesgo; 2) requieren validación; 3) disruptivos.
- **Anillos** en flota: piloto → 10 % → 50 % → 100 %, con *health gates* y rollback automático.
- Ventanas de mantenimiento y agrupación de reinicios.

## `adarve harden`: motor de remediación ✅

Diseño completo en [05-remediacion-segura.md](05-remediacion-segura.md). Resumen:

- Pipeline `PLAN → SNAPSHOT → APLICAR → VERIFICAR → COMMIT | ROLLBACK`.
- Simulación (`--dry-run`) por defecto, con diff.
- Ficheros *drop-in* en Linux (`/etc/sysctl.d/`, `/etc/ssh/sshd_config.d/`...).
- Tiene en cuenta GPO e Intune: no cambia en local lo que gestiona una directiva.
- *Dead-man switch* para cambios que afectan al acceso remoto.

## `adarve studio`: perfiles como código 🔜

- Editor visual de perfiles con herencia, parámetros y overrides por etiqueta, OU o grupo.
- **Importar**: Microsoft Security Baselines, GPO existentes, SCAP/XCCDF.
- **Exportar**: backup de GPO, Intune (Settings Catalog / OMA-URI), PowerShell DSC, rol de Ansible, scripts, SCAP/XCCDF y OSCAL.
- Comparador de perfiles y matriz de solapamiento CIS/STIG/Microsoft.

---

# 3. DEFENDER

## `adarve guard`: vigilancia continua 🔜

- Basado en eventos: `RegNotifyChangeKeyValue` y eventos 4719, 4739, 7040, 4946–4950 y Defender 5001/5007 en Windows; inotify/fanotify, auditd y señales D-Bus en Linux.
- Respuesta por control: alertar (por defecto), reparar sola, o reparar y alertar.
- Atribución con SACL (evento 4657): qué proceso y qué usuario hizo el cambio.
- Señales de manipulación como alerta crítica: logs borrados (1102/104), Defender desactivado, auditd detenido, agente parado.

## `adarve telemetry`: visibilidad y logging 🔜

- Baseline de logging: Advanced Audit Policy, eventos 4688 con línea de comandos, logging de PowerShell, Sysmon gestionado, tamaño de logs y WEF en Windows; reglas de auditd, journald persistente y reenvío por TLS en Linux.
- **Verificación de extremo a extremo** con eventos canario consultados en el SIEM.
- Segunda capa ATT&CK: técnicas **detectables** con los logs disponibles.

## `adarve hunt`: higiene y revisión rápida de compromiso 🔜

Solo lectura:

- **Persistencia**: Run/RunOnce, Winlogon, IFEO, servicios, tareas, suscripciones WMI, BITS, paquetes LSA; cron, systemd, `ld.so.preload`, PAM, `authorized_keys`, udev.
- **Integridad**: firmas Authenticode; `rpm -Va` / `debsums`.
- **Credenciales expuestas**: `unattend.xml`, GPP, claves sin passphrase, historiales.
- Binarios SUID/SGID nuevos.
- **Diferencias con el escaneo anterior**: qué ha aparecido de nuevo.
- Reglas YARA y Sigma opcionales.

## `adarve lockdown`: contención de emergencia 🔜

| Nivel | Acción |
|---|---|
| `restrict` | Bloquea el movimiento lateral entrante salvo desde IPs de gestión, deshabilita cuentas, cierra sesiones |
| `isolate` | Aislamiento de red total salvo el servidor Adarve y las IPs permitidas |

Recoge evidencias antes de aislar, tiene caducidad (TTL) con reversión automática y exige el rol de respuesta a incidentes, un motivo y MFA. Todo queda en el log de auditoría.

---

# 4. GOBERNAR

## `adarve report`: informes y evidencias ✅ / 🔜

- ✅ Consola, JSON estable (`adarve.report/v1`) y HTML autocontenido (claro/oscuro, filtros, ATT&CK, evidencias, remediación, imprimible).
- 🔜 Informes ejecutivo, técnico, por marco (CIS, STIG, NIST, ISO 27001, ENS, PCI-DSS 4.0, NIS2), diferencial (antes/después) y paquete de auditoría firmado.
- 🔜 Formatos PDF, CSV, XCCDF/ARF y OSCAL; marca blanca y envío programado.

## `adarve exceptions`: riesgo aceptado ✅ / 🔜

**Qué resuelve:** responde a "este control falla, lo sabemos y lo hemos aceptado" sin esconder el fallo para siempre.

```bash
sudo adarve exceptions add LNX-FW-001 --reason "Filtrado en el cortafuegos perimetral FW-02" --expires 90d
adarve exceptions list
sudo adarve exceptions remove LNX-FW-001
```

- ✅ Cada excepción lleva **motivo** (obligatorio), **responsable** y **caducidad** obligatoria de como mucho un año. Puede limitarse a equipos concretos (`--host`), útil si se distribuye el mismo fichero a varios.
- ✅ Un control fallido con excepción vigente aparece como **excepción**: no cuenta en la puntuación y `harden` no lo toca. Un control que pasa no cambia.
- ✅ Al **caducar**, el control vuelve a contar como fallido y cada escaneo lo avisa (consola e informe).
- ✅ Se guardan en `exceptions.yaml` (`adarve.exceptions/v1`) junto a `config.yaml`: solo un administrador puede modificarlas.
- 🔜 Flujo completo en la consola de flota: solicitud → aprobación a cuatro ojos → caducidad → reevaluación, con controles compensatorios.

## `adarve rules`: SDK de reglas ✅ / 🔜

```
adarve rules list [--all]      ✅ reglas aplicables (o todas)
adarve rules show <ID>         ✅ detalle, remediación y referencias
adarve rules lint [dir…]       ✅ validar el paquete oficial y reglas propias
adarve rules doc               ✅ catálogo en Markdown
adarve rules new               🔜 esqueleto de regla
adarve rules test              🔜 fixtures pass/fail con sistema simulado
adarve pack build --sign       🔜 paquete firmado
```

## API e integraciones 🔜

- REST (OpenAPI) y webhooks (`scan.completed`, `drift.detected`, `lockdown.started`…).
- SIEM: syslog CEF/LEEF, Elastic (ECS), Splunk HEC, Sentinel, Wazuh.
- ITSM: Jira y ServiceNow. Notificaciones: Slack, Teams y email.
- ✅ CI/CD hoy: `adarve scan --format json` y `--min-score`.

---

# Ideas avanzadas (fase 5 en adelante)

- **Copiloto IA (opcional)**: explica hallazgos y responde a "¿qué romperá esto?" con los metadatos de la regla y los datos de `observe`. Puede funcionar con un modelo local en redes aisladas.
- **Grafo de rutas de ataque**: de un portátil a Domain Admin y qué control corta cada camino.
- **Contenedores y nube**: CIS Docker/Kubernetes y líneas base para la nube.
