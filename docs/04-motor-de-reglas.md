# 04 · Motor de reglas

Las reglas son **datos declarativos en YAML**: describen qué leer del sistema y qué valor se espera. No contienen código ejecutable, así que un paquete de reglas no puede ejecutar nada en el equipo ([ADR-0002](adr/0002-reglas-declarativas.md)).

- Paquete oficial: `rules/linux/`, `rules/windows/`, `rules/profiles/`. Va incrustado en el binario.
- Reglas propias: cualquier `*.yaml` en `rules.d` (`/etc/adarve/rules.d` o `%ProgramData%\Adarve\rules.d`) o en `--rules-dir`.
- Esquema para editores: [`rules/schema/rule.schema.json`](../rules/schema/rule.schema.json).
- Validación: `adarve rules lint [directorio]` (también se ejecuta en CI y al arrancar cada comando).
- Estabilidad: el formato es estable en toda la versión 1 ([16 · Formatos estables y compatibilidad](16-formatos-y-compatibilidad.md)).

## Anatomía de una regla

```yaml
id: WIN-NET-006                    # PLATAFORMA-CATEGORÍA-NNN, en mayúsculas y único
title: LLMNR deshabilitado
description: La resolución de nombres multicast (LLMNR) debe estar deshabilitada.
rationale: Herramientas como Responder envenenan LLMNR para capturar hashes NTLM.
category: Red                      # agrupación en informes y puntuación por categoría
severity: high                     # critical | high | medium | low | info
platforms: [windows]               # ver "Plataformas"
requires: []                       # opcional: etiquetas que el equipo debe tener TODAS
profiles: [win-workstation-l1, win-server-l1]
references:
  nist: [CM-7, SC-20]
  cis: []                          # ver docs/14-marcos-y-licencias.md
  stig: []
  ens: []
  mitre_mitigations: [M1042, M1037]
  mitre_techniques: [T1557.001]
check:                             # QUÉ se comprueba
  probe: registry
  path: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
  name: EnableMulticast
  op: eq
  expected: 0
  default: 1                       # valor del sistema si la clave no existe
remediation:                       # CÓMO corregirlo
  summary: Habilitar la directiva "Turn off multicast name resolution".
  gpo: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution
  commands: reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
  breaking_risk: low               # none | low | medium | high (decide la ola de harden)
  reboot_required: false
  safety: remote-access            # opcional: puede cortar SSH/RDP → dead-man switch
  actions:                         # opcional: corrección automática (docs/05)
    - type: registry.set
      path: 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
      name: 'EnableMulticast'
      value: 0
impact: Texto opcional sobre lo que puede romperse al aplicarlo.
```

Un fichero puede contener varias reglas separadas por `---`. Los campos desconocidos producen un error de carga, así se detectan erratas.

## Plataformas

Las etiquetas del equipo van de la más específica a la más general. Una regla aplica si alguna de sus `platforms` está entre las etiquetas del equipo.

| Equipo | Etiquetas |
|---|---|
| Windows 10/11 | `windows-client`, `windows` |
| Windows Server miembro | `windows-member`, `windows-server`, `windows` |
| Controlador de dominio | `windows-dc`, `windows-server`, `windows` |
| Ubuntu | `linux-ubuntu`, `linux-debian`, `linux` |
| Debian | `linux-debian`, `linux` |
| RHEL / Rocky / Alma / CentOS | `linux-rhel`, `linux-fedora`, `linux` (según `ID_LIKE`) |

Etiquetas adicionales de estado:

| Etiqueta | Cuándo |
|---|---|
| `windows-joined` | El equipo está unido a un dominio de Active Directory o a Entra ID |
| `sudo-classic` | El sudo instalado es el clásico (sudo.ws), no sudo-rs |
| `sudo-rs` | El sudo instalado es sudo-rs (por defecto en Ubuntu 25.10 y posteriores): no admite `Defaults logfile` (registra en syslog) y tiene `use_pty` activado por defecto. Se detecta por la ruta de `/usr/bin/sudo` (`/usr/lib/cargo/bin`) o, si no basta, por `sudo --version` |

### `requires`: condiciones que deben cumplirse todas

`platforms` se cumple si el equipo tiene **alguna** de las etiquetas. `requires` exige **todas**; si falta una, la regla no se evalúa y aparece como **no aplica**, con el motivo. Ejemplo: LAPS solo tiene sentido en equipos gestionados:

```yaml
platforms: [windows-client, windows-member]
requires: [windows-joined]
```

## Perfiles

```yaml
id: win-dc-l1
name: Controlador de dominio · Nivel 1
description: ...
platforms: [windows-dc]
extends: [win-server-l1]           # hereda todas las reglas de ese perfil
default_for: [windows-dc]          # perfil por defecto para esa etiqueta
```

Un perfil incluye las reglas que lo nombran a él **o a cualquiera de sus ancestros**. Por eso `win-dc-l1` incluye la base de servidor más los controles específicos de DC. El perfil por defecto se elige recorriendo las etiquetas del equipo de la más específica a la más general.

## Comprobaciones (`check`)

### Hoja

| Campo | Descripción |
|---|---|
| `probe` | Recolector a usar (tabla siguiente) |
| *parámetros del probe* | `path`, `name`, `key`, `unit`... según el probe |
| `field` | Campo de la observación a comparar (por defecto, el del probe). Admite rutas con puntos: `Domain.Enabled` |
| `op` | Operador |
| `expected` | Valor esperado |
| `default` | Valor que se asume si el elemento no existe (el valor por defecto del sistema operativo) |
| `on_missing` | Si no existe y no hay `default`: `fail` (por defecto), `pass` o `na` |
| `each` | Si el valor es una lista: `all` (todos cumplen) o `any` (alguno cumple) |
| `label` | Nombre de la subcomprobación en los informes |

### Compuestas

```yaml
check:
  any:                                  # cumple si cumple alguna
    - {label: no disponible, probe: kmod, name: cramfs, field: available, op: eq, expected: false}
    - all:                              # cumple si cumplen todas
        - {label: no cargado, probe: kmod, name: cramfs, field: loaded, op: eq, expected: false}
        - {label: bloqueado, probe: kmod, name: cramfs, field: install_disabled, op: eq, expected: true}
```

| Resultado de los hijos | `all` | `any` |
|---|---|---|
| Algún `fail` | `fail` | `fail` si ninguno pasa |
| Algún `error` (sin `fail`) | `error` | `error` si ninguno pasa ni falla |
| Algún `skipped` (sin `fail` ni `error`) | `skipped` | `skipped` si ninguno pasa, falla ni da error |
| Todos `na` | `na` | `na` |
| Resto | `pass` | `pass` si alguno pasa |

Los `na` no penalizan dentro de un `all`. Así una regla "IPv4 e IPv6" pasa en un equipo sin IPv6.

Con `each`, la evidencia agrupa los valores repetidos y dice cuántos elementos cumplen, por ejemplo `actual 0 ×8, 2 (cumplen 1 de 9)`.

### Falta de privilegios

Un probe devuelve `PrivilegeError` cuando el dato solo se puede leer como administrador o root: `secedit`, `auditpol`, `Get-BitLockerVolume` o `Get-WindowsOptionalFeature` sin elevar, o un fichero como `/etc/shadow` sin root. Las consultas que Windows solo responde elevado ni siquiera se lanzan. El motor lo marca como `skipped` ("sin evaluar"): no es un fallo del control ni un error de Adarve. Con privilegios, un "permiso denegado" (SELinux, una ACL inusual) sí es un `error`.

### Patrón "la directiva prevalece sobre la configuración local"

```yaml
check:
  any:
    - {label: directiva, probe: registry, path: HKLM\SOFTWARE\Policies\...\Terminal Services, name: UserAuthentication, op: eq, expected: 1}
    - all:
        - {label: sin directiva, probe: registry, path: HKLM\SOFTWARE\Policies\...\Terminal Services, name: UserAuthentication, op: absent}
        - {label: local, probe: registry, path: HKLM\SYSTEM\...\RDP-Tcp, name: UserAuthentication, op: eq, expected: 1, default: 1}
```

## Operadores

| `op` | Cumple si… | Ejemplo |
|---|---|---|
| `eq` / `ne` | igual / distinto. Los números se comparan numéricamente ("14" = 14), los textos sin distinguir mayúsculas, y los booleanos aceptan true/false/yes/no/1/0 | `expected: 0` |
| `gt` `gte` `lt` `lte` | comparación numérica | `op: gte, expected: 14` |
| `between` | dentro del rango, ambos extremos incluidos | `expected: [1, 5]` |
| `in` / `not_in` | está / no está en la lista | `expected: [1, 2]` |
| `contains` / `not_contains` | la lista (o el texto) contiene todos / ninguno | `expected: [nodev, nosuid]` |
| `regex` / `not_regex` | expresión regular (sintaxis RE2) | `expected: "(?i)(cbc\|3des)"` |
| `bits_set` | todos los bits de `expected` activos | auditoría: `expected: 3` |
| `bits_clear` | ningún bit de `expected` activo | Kerberos sin DES/RC4: `7` |
| `bits_any` | algún bit de `expected` activo | AES permitido: `24` |
| `mode_max` | permisos octales no más permisivos que `expected` | `expected: "0640"` (entre comillas) |
| `exists` / `absent` | el elemento existe / no existe | |

## Probes

Todos son de **solo lectura**. Los comandos que ejecutan están fijados en el código; en Windows se invocan con ruta absoluta (`%SystemRoot%\System32\...`).

### Multiplataforma

| Probe | Parámetros | Campos | Notas |
|---|---|---|---|
| `file_content` | `path` | `value` | Contenido recortado de un fichero pequeño (`/sys`, `/proc`) |
| `file_regex` | `path` (lista y globs), `pattern`, `ignore_comments` (true) | `count`, `matches`, `files` | Cuenta líneas que coinciden |
| `file_kv` | `path` (lista y globs), `key`, `separator` (espacio por defecto), `case_insensitive` | `value`, `file` | Gana la última aparición (semántica de drop-ins) |

### Linux

| Probe | Parámetros | Campos | Notas |
|---|---|---|---|
| `sysctl` | `key` | `value` | Valor en ejecución desde `/proc/sys` |
| `file` | `path` (o lista: usa el primero que exista) | `mode` ("0644"), `owner`, `group`, `uid`, `gid`, `type`, `size` | |
| `sshd` | `key` (en minúsculas) | `value` | `sshd -T` (configuración efectiva) o, sin root, interpretación de `sshd_config` + `Include` con la regla "gana la primera". `na` si no hay OpenSSH server |
| `kmod` | `name` | `loaded`, `available`, `install_disabled`, `blacklisted`, `install_command` | `na` en contenedores |
| `systemd` | `unit` | `enabled` (UnitFileState), `active` (ActiveState), `load_state` | `na` si systemd no está en ejecución |
| `mount` | `path` | `mounted`, `options` (lista), `fstype`, `source` | `/proc/self/mountinfo` |
| `package` | `name` | `installed`, `version` | dpkg o rpm |

### Windows

| Probe | Parámetros | Campos | Notas |
|---|---|---|---|
| `registry` | `path` (HKLM/HKU/HKCR; admite un segmento con `*`), `name` | `value`, `type` | Vista de 64 bits. Con comodín devuelve una lista (usar `each`) |
| `secpol` | `section` (System Access, Privilege Rights, Registry Values…), `key` | `value` | Un único `secedit /export` por escaneo. Privilege Rights devuelve lista de SIDs |
| `auditpol` | `guid` (subcategoría, sin llaves) | `value` (0 nada, 1 aciertos, 2 errores, 3 ambos), `name` | `auditpol /backup`: valores numéricos, independientes del idioma |
| `service` | `name` | `start_type` (auto, auto-delayed, manual, disabled…), `state`, `display_name` | API del Service Control Manager |
| `ps` | `query` (de la lista blanca) | según la consulta | Ver tabla siguiente |

Consultas PowerShell permitidas (`ps`). La regla elige el nombre; el código es fijo:

| `query` | Origen | Campos de ejemplo |
|---|---|---|
| `smb_server` | `Get-SmbServerConfiguration` | `EnableSMB1Protocol`, `RequireSecuritySignature`, `EncryptData` |
| `smb_client` | `Get-SmbClientConfiguration` | `RequireSecuritySignature`, `EnableInsecureGuestLogons` |
| `firewall` | `Get-NetFirewallProfile -PolicyStore ActiveStore` | `Domain.Enabled`, `Public.DefaultInboundAction` |
| `defender_status` | `Get-MpComputerStatus` | `RealTimeProtectionEnabled`, `IsTamperProtected`, `AntivirusSignatureAge` |
| `defender_prefs` | `Get-MpPreference` | `MAPSReporting`, `PUAProtection`, `EnableNetworkProtection` |
| `defender_asr` | `Get-MpPreference` | `<guid-de-la-regla-ASR>` → 0 off, 1 bloquear, 2 auditar, 6 avisar |
| `bitlocker_os` | `Get-BitLockerVolume` (unidad del sistema) | `ProtectionStatus`, `EncryptionMethod`, `KeyProtectors` |
| `device_guard` | `Win32_DeviceGuard` | `SecurityServicesRunning` (1 Credential Guard, 2 HVCI) |
| `optional_features` | `Get-WindowsOptionalFeature` | `SMB1Protocol`, `MicrosoftWindowsPowerShellV2Root` |
| `smb_shares` | `Get-SmbShare` + `Get-SmbShareAccess` (sin los administrativos) | `shares[].Name`, `Path`, `Access[].SID`, `Right` (la usa `adarve surface`) |
| `local_admins` | Miembros de S-1-5-32-544 (`Get-LocalGroupMember` o ADSI) | `members[].Name`, `Type`, `Source` (la usa `adarve surface`) |
| `firewall_profiles` | `HNetCfg.FwPolicy2`: solo los perfiles (las reglas se leen del registro) | `profiles[].Enabled`, `BlockInbound`, `Active` (la usa `adarve surface`) |
| `firewall_policy` | `HNetCfg.FwPolicy2`: perfiles y reglas de entrada habilitadas | Igual, más `rules[]` (la usa `adarve surface` si no puede leer el registro) |

Las consultas que Windows solo responde con un token elevado (`bitlocker_os`, `optional_features`, `smb_shares`) no se lanzan sin privilegios: el control queda **sin evaluar**.

Si Defender o BitLocker no están disponibles, la consulta devuelve `na` con el motivo y no un fallo.

## Guía de estilo para escribir reglas

1. **Un control, una idea.** Si hay dos cambios independientes, son dos reglas.
2. **Lee el valor efectivo** (`sshd -T`, *ActiveStore*), no el fichero de configuración.
3. **Declara el `default` del sistema operativo** cuando el valor puede no existir. Es la diferencia entre un falso positivo y un resultado correcto.
4. **`on_missing: na`** cuando la ausencia significa "no aplica" (sin IPv6, sin Yama, sin sshd).
5. **`breaking_risk` e `impact` honestos.** Son la base del planificador y de la confianza del usuario.
6. **Remediación accionable**: ruta de GPO completa y comandos idempotentes. En Linux, con ficheros *drop-in*.
7. **Referencias**: al menos NIST y, cuando aplique, técnicas y mitigaciones ATT&CK verificadas.
8. Valida con `adarve rules lint` y regenera el catálogo con `adarve rules doc > docs/06-...`.
