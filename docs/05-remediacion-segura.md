# 05 · Remediación segura (`bastion harden`)

> Estado: ✅ implementado en la v0.2.0. 121 de los 155 controles tienen corrección automática.

## Objetivo

Aplicar hardening **sin miedo**: cada cambio es simulable, reversible, verificado y auditado.

## Uso

```bash
bastion harden                         # SIMULACIÓN de la ola 1: muestra el plan, no cambia nada
bastion harden --apply                 # aplicar la ola 1 (pide confirmación)
bastion harden --wave 2 --apply        # incluir cambios de riesgo medio
bastion harden --rule WIN-NET-006 --apply
bastion harden --include-remote --apply   # incluir SSH/RDP (con dead-man switch)
bastion history                        # cambios aplicados
bastion rollback                       # deshacer el último cambio
bastion rollback chg-20261015-193000   # deshacer uno concreto
```

| Opción | Descripción |
|---|---|
| `--apply` | Aplicar. Sin ella es una simulación |
| `-w, --wave 1\|2\|3` | Ola máxima por riesgo de rotura (por defecto 1) |
| `-p, --profile` | Perfil (por defecto, el del rol del equipo) |
| `--rule`, `--category` | Limitar a reglas o categorías |
| `-y, --yes` | No pedir confirmación |
| `--include-remote` | Incluir cambios que pueden cortar el acceso remoto |
| `--confirm-timeout 2m` | Plazo del dead-man switch |
| `--no-deadman` | Sin dead-man switch (solo máquinas desechables o laboratorios) |
| `--force-local` | Aplicar en local valores que gestiona una GPO de dominio |

Requiere administrador (Windows) o root (Linux).

## Ejemplo de simulación

```text
  ▲ BASTION  · plan de hardening  0.2.0
  Equipo    web-01 · Ubuntu 24.04.1 LTS
  Perfil    Linux Servidor · Nivel 1 (linux-server-l1)
  Ola       1 · riesgo de rotura nulo o bajo
  Postura   65/100 D · 15 controles fallidos

  CAMBIOS QUE SE APLICARÁN (9)
  MEDIO    LNX-KRN-002   Ocultar direcciones del kernel (kptr_restrict)  riesgo ninguno
                         · sysctl kernel.kptr_restrict: 0 → 2  (/etc/sysctl.d/60-bastion.conf)
  BAJO     LNX-AUTH-003  Caducidad máxima de contraseñas  riesgo bajo
                         · /etc/login.defs: PASS_MAX_DAYS 99999 → 365
  ...
  REQUIEREN UNA OLA SUPERIOR (1)  → bastion harden --wave 2 | 3
  REMEDIACIÓN MANUAL (5)          → bastion rules show <ID>

  ⚠ Simulación: no se ha cambiado nada.
    Para aplicar: bastion harden --apply
```

## Pipeline transaccional

```
  PLAN ──► (por cada control) INSTANTÁNEA ──► APLICAR ──► VERIFICAR ──┬──► ✓ se mantiene
   │                │                                                  │
   │                └─ estado previo exacto en snapshots/<id>/         └──► ✗ ROLLBACK de ese control
   └─ diff "actual → nuevo", riesgo de rotura, reinicio, qué es manual
```

1. **Plan.** Se evalúan los controles. Para cada fallo con acciones, se clasifica (aplicable, otra ola, acceso remoto, GPO, manual) y se captura el estado actual para mostrar el diff. Todo de solo lectura.
2. **Instantánea con registro previo.** Justo antes de cada acción se vuelve a capturar el estado y se escribe en `snapshots/<id>/manifest.json` **antes** de aplicar. Si el proceso muere a mitad, el rollback también restaura esa entrada.
3. **Aplicar.** Acciones tipadas, idempotentes y en orden determinista.
4. **Verificar.** Se vuelve a evaluar el control con una caché nueva.
   - Si se cumple, el cambio se mantiene.
   - Si no se cumple, se revierte y se marca como **sin efecto**. Pasa, por ejemplo, si Tamper Protection o una GPO lo anulan.
   - Si la acción da error, se revierte y se marca como **error**.
5. **Resumen** con la postura antes y después, el ID de la instantánea y el aviso de reinicio si hace falta.

## Acciones disponibles

**No existe un tipo "ejecutar comando"** ([ADR-0004](adr/0004-sin-ejecucion-arbitraria.md)). Los parámetros se validan con listas blancas y expresiones regulares, también en `bastion rules lint`, para impedir rutas fuera de lugar, saltos de línea inyectados en ficheros de configuración o cmdlets no previstos.

### Windows

| Tipo | Parámetros | Qué hace | Cómo se restaura |
|---|---|---|---|
| `registry.set` | `path` (HKLM, admite un `*`), `name`, `value`, `value_type` (DWORD, QWORD, SZ) | Crea la clave si hace falta y escribe el valor | Valor y tipo anteriores, o se elimina si no existía |
| `secpol.set` | `section: System Access`, `key` (lista blanca), `value` | `secedit /configure` con una plantilla INF temporal | Valor anterior |
| `auditpol.set` | `guid`, `success`, `failure` | `auditpol /set` (solo activa lo indicado) | Aciertos y errores exactamente como estaban |
| `service.config` | `name`, `start_type` (disabled, manual, auto), `stop` | API del Service Control Manager | Tipo de inicio (incluido el retrasado) y estado |
| `defender.asr` | `guid`, `mode` (block, audit, warn, disabled) | `Add-MpPreference` | Modo anterior, o `Remove-MpPreference` si no existía |
| `defender.pref` | `name` (PUAProtection, MAPSReporting, EnableNetworkProtection, SubmitSamplesConsent), `value` | `Set-MpPreference` | Valor anterior |

### Linux

| Tipo | Parámetros | Qué hace | Cómo se restaura |
|---|---|---|---|
| `sysctl.set` | `key`, `value`, `optional` | Escribe en `/etc/sysctl.d/60-bastion.conf` y en el kernel en ejecución | Fichero y valor en ejecución anteriores |
| `sshd.set` | `key`, `value` | Escribe en `/etc/ssh/sshd_config.d/00-bastion.conf`, **valida con `sshd -t`** y recarga | Fichero anterior + recarga. Si la validación falla, no se aplica |
| `kmod.block` | `name` | `/etc/modprobe.d/bastion-<módulo>.conf` (install /bin/false + blacklist) y descarga | Fichero anterior; recarga el módulo si estaba cargado |
| `systemd.disable` | `unit`, `mask` | `systemctl disable/mask --now` | `unmask`, `enable` y `start` según el estado anterior |
| `file.mode` | `path` (o lista), `mode`, `owner`, `group` (o lista) | `chmod` / `chown` | Permisos y propietario anteriores |
| `file.kv_set` | `path` (bajo /etc), `key`, `value`, `separator` | Sustituye la clave activa o la añade | Contenido anterior completo del fichero |
| `sudoers.defaults` | `option` (lista blanca) | `/etc/sudoers.d/00-bastion` (0440), **validado con `visudo -c`** | Fichero anterior |
| `firewall.remote_address` (Windows) | `rule` (nombre interno), `remote` (solo `LocalSubnet`) | `Set-NetFirewallRule` sobre la regla exacta del almacén local; el nombre llega a PowerShell por una variable de entorno, nunca dentro del script. Lo usa `bastion surface fix` | Direcciones remotas anteriores (validadas) |

Principio: en Linux se usan **ficheros drop-in** propios en lugar de editar los originales (salvo `login.defs`, que no admite drop-ins). El rollback es limpio y no choca con las actualizaciones de paquetes.

### En las reglas

```yaml
remediation:
  summary: Habilitar la directiva "Turn off multicast name resolution".
  breaking_risk: low
  actions:
    - type: registry.set
      path: 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
      name: 'EnableMulticast'
      value: 0
```

Una regla puede tener varias acciones; se aplican en orden y, si una falla, se revierten las anteriores de esa misma regla. Una regla sin `actions` es de remediación manual.

## Salvaguardas

### Olas por riesgo de rotura

| Ola | `breaking_risk` | Ejemplos |
|---|---|---|
| 1 (por defecto) | `none`, `low` | Auditoría, logging de PowerShell, WDigest, ASR LSASS, LLMNR, sysctl de red |
| 2 | + `medium` | NTLMv2 obligatorio, NetBIOS, LSA protegido, rp_filter, rpcbind |
| 3 | + `high` | Kerberos solo AES, firma LDAP obligatoria, solo autenticación SSH por clave |

### Dead-man switch para el acceso remoto

Las reglas con `safety: remote-access` (RDP NLA; en SSH, el acceso de root, los cifrados, los MAC, el intercambio de claves y la autenticación por contraseña) se omiten salvo que se pase `--include-remote`. Con esa opción:

1. Se aplican los demás cambios.
2. Se arma un **proceso independiente** (`bastion deadman <id>`) que sobrevive al cierre de la sesión SSH o RDP.
3. Se aplican los cambios de acceso remoto y se verifican.
4. Bastion pide que abras **una sesión nueva** y escribas `confirmar`. Si no lo haces dentro del plazo (por defecto 2 minutos), o si la sesión se corta, los cambios de acceso remoto se revierten solos.

En modo no interactivo (`--yes`) los cambios remotos se rechazan, salvo que se indique `--no-deadman` (pensado para máquinas desechables y CI).

### Consciencia de GPO

En un equipo unido a dominio, las acciones sobre claves `...\Policies\...` se marcan como **gestionadas por GPO** y no se aplican en local, porque la directiva las volvería a sobrescribir en el siguiente `gpupdate`. Corrígelas en la GPO o usa `--force-local`.

### Otras

- **Un único hardening a la vez** (bloqueo del sistema, `flock` o `LockFileEx`, sobre `snapshots/.lock`; si el proceso muere, el sistema lo libera).
- Durante la ejecución se ignora `SIGHUP`: si se corta la sesión SSH, Bastion termina el cambio en curso en lugar de quedarse a medias.
- `changes.log` registra cada evento (aplicado, sin efecto, error, deshecho, dead-man) en JSON, uno por línea.

## Instantáneas

```
<datos>/snapshots/
├── changes.log
└── chg-20261015-193000/
    ├── manifest.json      ← estado previo de cada acción (bastion.change/v1)
    └── deadman.log        ← solo si hubo cambios de acceso remoto
```

`<datos>` es `/var/lib/bastion` en Linux y `C:\ProgramData\Bastion` en Windows, con los mismos permisos restringidos que el resto de Bastion.

```json
{
  "schema": "bastion.change/v1",
  "id": "chg-20261015-193000",
  "status": "applied",
  "entries": [
    { "seq": 1, "rule_id": "WIN-NET-006",
      "action": { "type": "registry.set", "path": "HKLM\\SOFTWARE\\Policies\\...\\DNSClient", "name": "EnableMulticast", "value": 0 },
      "description": "HKLM\\...\\EnableMulticast: (no existe) → 0 (DWORD)",
      "before": { "values": [ { "sub": "SOFTWARE\\Policies\\...\\DNSClient", "exists": false } ] },
      "attempted": true, "applied": true }
  ],
  "rules": [ { "rule_id": "WIN-NET-006", "outcome": "verified" } ]
}
```

## Pendiente

- 🔜 *Health checks* personalizados (HTTP 200 en tu aplicación, puerto TCP abierto) después de aplicar.
- 🔜 Detección precisa de GPO e Intune mediante RSoP, en lugar de la heurística por ruta.
- 🔜 Puntos de restauración del sistema (Windows) e instantáneas LVM/btrfs (Linux) opcionales.
- 🔜 Más acciones: características opcionales de Windows (SMBv1, PowerShell 2.0), firewall, montajes.
- 🔜 Exportar el plan como GPO, Intune, Ansible o DSC (`studio`).
