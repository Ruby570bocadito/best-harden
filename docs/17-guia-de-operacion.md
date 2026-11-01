# 17 · Guía de operación

Cómo desplegar Adarve en muchos equipos (GPO, Intune y Ansible), cómo llevar el hardening a la flota sin sustos y qué hacer cuando algo sale mal: un rollback que falla, un acceso remoto perdido, una ronda que no se ejecuta.

Los ejemplos están en [`deploy/`](../deploy) y el CI los ejecuta en máquinas reales contra un espejo firmado con una clave de prueba (job «Despliegue de ejemplo»): el playbook de Ansible, el script de despliegue de Windows desde un PowerShell de 64 y de 32 bits, y los scripts de Intune. Lo que el CI no puede probar es la parte de la propia GPO o de Intune: enlazar la directiva o subir el paquete.

## Antes de desplegar

- **Fija una versión** (`v0.5.0`), no «la última»: todos los equipos llevan la misma y actualizas cuando tú decides. Los ejemplos la exigen.
- **Sirve la release desde dentro**: un recurso compartido (Windows) o un espejo HTTPS ([09 · Instalación](09-instalacion.md#redes-aisladas-y-espejos-internos)), con su `checksums.txt.sig`. Sin la firma no se instala, y la firma protege aunque alguien manipule la carpeta.
- **Protege la carpeta de los scripts.** La firma cubre los archivos de la release, no `Deploy-Adarve.ps1` ni `install.ps1`, que se ejecutan como SYSTEM en todos los equipos. Quien pueda modificarlos controla la flota: lectura para los equipos y escritura solo para administradores.
- **Empieza por un grupo piloto**: un par de equipos de cada tipo (servidor, puesto, portátil de administrador). Los despliegues solo instalan, programan la ronda diaria y auditan: no cambian la configuración del equipo. El hardening va después, por olas ([más abajo](#llevar-el-hardening-a-la-flota)).

## Windows

### La carpeta de despliegue

Los tres métodos usan la misma carpeta: el instalador, los ficheros de la release sin cambiar y [`Deploy-Adarve.ps1`](../deploy/windows/Deploy-Adarve.ps1).

```
\\fs01\software$\adarve\v0.5.0\
├── Deploy-Adarve.ps1          deploy/windows/ del repositorio
├── install.ps1                scripts/ del repositorio
├── checksums.txt              de la release
├── checksums.txt.sig          de la release
├── adarve_windows_amd64.zip
└── adarve_windows_arm64.zip   solo si hay equipos ARM
```

Una carpeta por versión: para actualizar, se crea la nueva y se cambian la ruta y `-Version` en un solo paso, y se puede volver a la anterior igual.

`Deploy-Adarve.ps1 -Version v0.5.0 [-At 09:00] [-NoSchedule]`:

1. Si la versión instalada ya es `-Version`, no reinstala. Si no, ejecuta `install.ps1 -Local` con el `.zip` de la arquitectura del equipo, que comprueba la firma y la suma antes de instalar, y después confirma que quedó esa versión.
2. Programa la ronda diaria a la hora `-At`, si no lo está ya.
3. Deja cada paso en `C:\ProgramData\Adarve-despliegue.log` y termina con código 0 (todo bien) o 1 (el motivo, en el registro).

Se puede ejecutar en cada arranque o cada hora: si no hay nada que hacer, termina en un par de segundos. También funciona desde un PowerShell de 32 bits, que es como el agente de Intune ejecuta las aplicaciones Win32.

### Por GPO

En una GPO vinculada a la unidad organizativa de los equipos, dentro de **Configuración del equipo**:

| Para | Dónde | Qué |
|---|---|---|
| Puestos, que se reinician a menudo | Directivas › Configuración de Windows › Scripts › **Inicio** › pestaña *Scripts* | Nombre: `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`. Parámetros: `-NoProfile -ExecutionPolicy Bypass -File "\\fs01\software$\adarve\v0.5.0\Deploy-Adarve.ps1" -Version v0.5.0` |
| Servidores, que casi no se reinician | Preferencias › Configuración del Panel de control › Tareas programadas › Nueva › **Tarea inmediata** | Usuario `NT AUTHORITY\System`, *Ejecutar con los privilegios más altos*; acción: el mismo programa con los mismos parámetros |

La tarea inmediata se ejecuta en cada refresco de la directiva (cada 90 minutos o con `gpupdate /force`): un equipo al que le quiten Adarve lo recupera solo. El script de inicio, en cada arranque.

Los scripts de inicio y las tareas como SYSTEM acceden a la red con la cuenta del equipo: el recurso compartido debe dar lectura a **Equipos del dominio**. Si no, el registro dice `Falta \\fs01\…\install.ps1`.

### Por Intune

**Aplicación Win32** (instalar y mantener la versión):

1. Empaqueta la carpeta de despliegue: `IntuneWinAppUtil.exe -c <carpeta> -s Deploy-Adarve.ps1 -o <salida>`.
2. Programa:
   - Instalar: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Deploy-Adarve.ps1 -Version v0.5.0`
   - Desinstalar: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1 -Uninstall`
   - Comportamiento de instalación: *Sistema*. Código 0 = correcto, 1 = error.
3. Detección: *Usar un script de detección personalizado* con [`Detect-Adarve.ps1`](../deploy/intune/Detect-Adarve.ps1), con `$Version` igual a la del paquete (Intune no le pasa parámetros). Funciona tanto en 64 como en 32 bits.
4. Para actualizar: un paquete nuevo con la versión nueva en `-Version` y en `$Version`. Intune deja de detectarlo como instalado y lo reinstala.

**Remediations** (la postura de cada equipo en la consola de Intune; necesitan licencias Windows Enterprise E3/E5 o equivalentes):

- Detección: [`Detect-Postura.ps1`](../deploy/intune/Detect-Postura.ps1), con el umbral en `$MinScore`. Hace una ronda de solo lectura y escribe una línea que Intune muestra por equipo: `Adarve 74/100 (C) - 14 fallidos de 128 - perfil win-workstation-l1 - umbral 80`. Por debajo del umbral, el equipo sale «con problemas».
- Corrección, opcional: [`Remediate-Postura.ps1`](../deploy/intune/Remediate-Postura.ps1) aplica la ola 1 de `harden` en los equipos con problemas. Asígnalo primero a un grupo piloto (ver [Llevar el hardening a la flota](#llevar-el-hardening-a-la-flota)).

### Por Ansible

El CI no puede conectarse a un Windows por WinRM, así que esta parte no está probada. `Deploy-Adarve.ps1`, sí:

```yaml
- name: Adarve en Windows
  hosts: windows
  tasks:
    - name: Carpeta temporal privada
      ansible.windows.win_tempfile:
        state: directory
      register: tmp
    - name: Copiar la carpeta de despliegue
      ansible.windows.win_copy:
        src: adarve-v0.5.0/          # la carpeta de despliegue, en el controlador
        dest: "{{ tmp.path }}\\"
    - name: Instalar o actualizar y programar la ronda
      ansible.windows.win_command: >-
        powershell.exe -NoProfile -ExecutionPolicy Bypass
        -File "{{ tmp.path }}\Deploy-Adarve.ps1" -Version v0.5.0 -At 09:00
      register: adarve
      changed_when: "' instalado en ' in adarve.stdout or 'Ronda diaria programada' in adarve.stdout"
    - name: Borrar la carpeta temporal
      ansible.windows.win_file:
        path: "{{ tmp.path }}"
        state: absent
```

No uses una carpeta fija en `C:\Windows\Temp` o `C:\ProgramData`: cualquier usuario puede crearla antes y cambiar el script entre la copia y la ejecución como SYSTEM.

## Linux con Ansible

[`deploy/ansible/adarve.yml`](../deploy/ansible/adarve.yml) instala o actualiza a la versión indicada con `scripts/install.sh` desde el controlador, sin `curl | bash` en cada equipo. Después programa la ronda diaria, hace una ronda y trae el informe de cada equipo.

```bash
ansible-playbook -i inventario deploy/ansible/adarve.yml -e adarve_version=v0.5.0
ansible-playbook -i inventario deploy/ansible/adarve.yml -e adarve_version=v0.5.0 \
  -e adarve_releases_url=https://mirror.interno/adarve -e adarve_min_score=80
```

| Variable | Por defecto | |
|---|---|---|
| `adarve_version` | — | Obligatoria: `vX.Y.Z` |
| `adarve_releases_url` | GitHub | Espejo interno (HTTPS) |
| `adarve_schedule_at` | `09:00` | Hora de la ronda diaria; vacío, sin ronda |
| `adarve_reports_dir` | `deploy/ansible/informes` | Dónde deja `<equipo>.json` (`adarve.report/v1`); vacío, no los trae |
| `adarve_min_score` | `0` | Mayor que 0: los equipos por debajo salen como fallidos en el resumen |
| `adarve_installer`, `adarve_prefix` | `scripts/install.sh`, `/usr/local/bin` | |

Se puede repetir: la segunda vez termina con `changed=0`. Solo instala si la versión es otra y solo programa si la hora cambia. La ronda guarda también el informe en la historia del equipo (`adarve ui`).

## Recoger los resultados

| Qué | Dónde |
|---|---|
| El último informe de cada equipo | `reports/` en la carpeta de datos ([rutas](09-instalacion.md#rutas)); con Ansible, `adarve_reports_dir`. Formato estable: [16](16-formatos-y-compatibilidad.md) |
| Avisos cuando algo empeora | Un webhook: `adarve schedule notify --set -` (ntfy, Slack, Discord, Teams o JSON `adarve.notify/v1`) |
| El registro de cada ronda | Visor de eventos › Aplicación, origen Adarve; en Linux, `journalctl -t adarve`. Y `schedule.log` en la carpeta de datos |
| La puntuación de cada equipo en Intune | Remediations, con `Detect-Postura.ps1` |

`--set -` lee la dirección del webhook por la entrada estándar, para que no quede en la línea de órdenes. No la pongas en los parámetros de una GPO: SYSVOL lo puede leer cualquier usuario del dominio. Mejor, una tarea inmediata que la lea de un fichero que solo puedan leer los equipos.

## Llevar el hardening a la flota

1. **Audita** una o dos semanas con la ronda diaria, para conocer la postura de partida.
2. **Simula** en los pilotos: `adarve harden` sin `--apply` enseña el plan, cambio por cambio.
3. **Aplica la ola 1 en los pilotos** (`adarve harden --apply`) y comprueba que todo sigue funcionando: aplicaciones, accesos, impresoras, copias de seguridad.
4. **Excepciones** para lo que deba quedarse como está: `adarve exceptions add <ID> --reason "…" --expires 90d`. `harden` no toca un control con una excepción vigente.
5. **Extiende la ola 1** por grupos: con Intune, `Remediate-Postura.ps1`; con Ansible, `ansible linux -b -m command -a "adarve harden --apply --yes --wave 1"`.
6. **Las olas 2 y 3**, de riesgo medio y alto, mejor equipo a equipo o por grupos pequeños, siempre después de probarlas en un piloto.

Siempre:

- Los cambios que pueden cortar SSH o RDP (`safety: remote-access`) necesitan `--include-remote` y una persona que confirme desde una sesión nueva. En modo desatendido (`--yes`) se rechazan, así que un despliegue masivo nunca los aplica.
- En un equipo del dominio, las claves `…\Policies\…` las gestiona la GPO: Adarve no las cambia en local, se corrigen en la GPO.
- Cada `harden` deja una instantánea: `adarve history` las lista y `adarve rollback <ID>` deshace una.

## Cuando algo sale mal

### Un rollback falla

```
Error: rollback incompleto: LNX-SSH-007 (sshd.set): …
```

Adarve deshace las entradas de un cambio en orden inverso y sigue con las demás aunque una falle. Las que deshace quedan marcadas; las que no, pendientes. Volver a ejecutar `adarve rollback <ID>` solo reintenta las pendientes.

1. **Lee el motivo**: en la salida, en el campo `error` de la entrada y en `snapshots/changes.log` (un evento JSON por línea; los fallos son `rollback-failed`).
2. **Arregla la causa y repite** `adarve rollback <ID>`:

   | Mensaje | Qué hacer |
   |---|---|
   | El servicio de Microsoft Defender no responde | Adarve ya reintenta a los 2, 5 y 10 s. Espera a que `Get-Service WinDefend` esté en *Running* y repite |
   | Un fichero o una clave en uso, o acceso denegado | Cierra el programa que los usa (o reinicia), comprueba que la consola es de administrador o root y repite |
   | `estado previo inválido en el manifiesto` | El manifiesto se ha modificado o dañado y Adarve no lo usa. Restaura a mano (abajo) |
   | `la acción … no está disponible en esta plataforma` | Es el manifiesto de otro sistema copiado aquí: no sirve en este equipo |

3. **Si no se puede con Adarve, restaura a mano.** El manifiesto guarda el estado exacto de antes de cada entrada (`before`):

   ```bash
   M=/var/lib/adarve/snapshots/chg-20261015-193000/manifest.json      # Windows: C:\ProgramData\Adarve\snapshots\…
   sudo jq '.entries[] | select(.attempted and (.rolled_back | not)) | {seq, rule_id, type: .action.type, error}' "$M"
   sudo jq -r '.entries[] | select(.rule_id == "LNX-SSH-007") | .before.content' "$M" | base64 -d   # el fichero de antes
   ```

   ```powershell
   $m = Get-Content C:\ProgramData\Adarve\snapshots\chg-20261015-193000\manifest.json -Raw | ConvertFrom-Json
   $m.entries | Where-Object { $_.attempted -and -not $_.rolled_back } | Format-List seq, rule_id, action, before, error
   ```

   | Acción | Qué guarda `before` | Cómo volver a dejarlo |
   |---|---|---|
   | `registry.set` | `values`: cada valor con su clave (`sub`) y si existía, su tipo y su dato | `reg add` con el tipo y el dato, o `reg delete` si no existía |
   | `secpol.set`, `auditpol.set` | el valor de la directiva | `secpol.msc` o `auditpol /set /subcategory:…` |
   | `service.config` | `start_type` (2 automático, 3 manual, 4 deshabilitado), `delayed`, `running` | `sc.exe config <servicio> start= auto\|demand\|disabled` y arrancarlo si estaba en marcha |
   | `defender.asr`, `defender.pref` | `present` y `mode`, o `value` | `Add-MpPreference` o `Set-MpPreference` con ese valor |
   | `firewall.remote_address` | `remote`, la regla y sus puertos | `Set-NetFirewallRule -RemoteAddress …` |
   | `sysctl.set` | `runtime` y el fichero (`file`: `exists`, `content` en base64, `mode`) | Restaura `/etc/sysctl.d/99-zz-bastion.conf` (o bórralo si no existía) y `sysctl -w <clave>=<runtime>` |
   | `sshd.set`, `sudoers.defaults`, `file.kv_set` | el fichero: `exists`, `content` en base64, `mode` | Restaura el fichero (o bórralo). Antes, `sshd -t` para sshd y `visudo -c -f <fichero>` para sudoers |
   | `kmod.block` | el fichero de `/etc/modprobe.d/` y si el módulo estaba cargado (`loaded`) | Restaura o borra el fichero y, si estaba cargado, `modprobe <módulo>` |
   | `systemd.disable` | `enabled` y `active` | `systemctl enable` o `start` según lo que hubiera |
   | `file.mode` | `path` y `mode` | `chmod`. El modo está en decimal: 420 es 0644 (`printf '%o' 420`) |

   Después, `adarve rollback <ID>` vuelve a escribir lo mismo y deja el cambio marcado como deshecho en `adarve history`.

### Un hardening se cortó a medias

Un corte de luz, un proceso matado o una sesión que se cae. Adarve anota cada entrada en el manifiesto **antes** de aplicarla, así que `adarve history` muestra el cambio como *interrumpido* y `adarve rollback <ID>` restaura también la entrada que se estaba aplicando. Si el bloqueo (`snapshots/.lock`) se quedó puesto, se libera solo a los 30 minutos.

### Perdiste el acceso remoto (SSH o RDP)

Con `--include-remote`, si no confirmas desde una sesión nueva en el plazo (2 minutos por defecto), el dead-man switch deshace solo los cambios de acceso remoto. **No reinicies el equipo mientras tanto**: hoy el dead-man switch es un proceso aparte que no sobrevive a un reinicio. Si el equipo se reinicia antes del plazo, los cambios se quedan.

Si el acceso no vuelve:

1. Entra por la consola: la del hipervisor, la consola serie del proveedor de nube, iLO o iDRAC. También sirve «ejecutar orden» del proveedor (AWS Systems Manager, Azure Run Command).
2. `adarve rollback` deshace el último cambio; `adarve rollback <ID>`, uno concreto.
3. ¿Sigues sin entrar por SSH? Al deshacer un cambio de sshd, Adarve restaura el fichero aunque sshd no recargue, porque lo leería al arrancar. Así que el sshd en marcha puede seguir con la configuración endurecida. Comprueba la configuración con `sshd -t` (el error suele estar en otro fichero de `sshd_config.d/`) y recarga: `systemctl reload ssh`, o `sshd` en RHEL.
4. `snapshots/<ID>/deadman.log` cuenta qué hizo el dead-man switch.

### Un cambio rompió una aplicación

`adarve history` para encontrar el cambio y `adarve rollback <ID>` para deshacerlo entero. Para conservar el resto: deshazlo, añade una excepción para el control que molesta (`adarve exceptions add <ID> --reason "…" --expires 90d`) y vuelve a aplicar. Ese control ya no se toca.

### La ronda diaria no se ejecuta

- `adarve schedule status` enseña la tarea y las últimas ejecuciones.
- Windows: Programador de tareas › `\Adarve\Escaneo diario` (pestaña Historial) y Visor de eventos › Aplicación, origen Adarve. Linux: `systemctl status adarve-scan.timer` y `journalctl -u adarve-scan.service`.
- `no se programa: … carpeta que otros usuarios pueden modificar`: el binario no está donde lo deja el instalador (`C:\Program Files\Adarve`, `/usr/local/bin`). Reinstala con el instalador.
- El código 3 no es un fallo: algún control ha empeorado o la exposición ha crecido desde la ronda anterior.

### Adarve ignora la configuración

Con privilegios, Adarve no usa `config.yaml`, `exceptions.yaml` ni `rules.d` si otros usuarios pueden modificarlos, y avisa. `adarve init` restablece los permisos y aparta los ficheros no fiables como `*.no-confiable-<fecha>`: revísalos antes de volver a usarlos.

### El despliegue falla

- Windows: `C:\ProgramData\Adarve-despliegue.log`.
  - `Falta …`: el fichero no está o los equipos no pueden leer la carpeta.
  - `es de otra versión`: el `.zip` no es el de `-Version`.
  - Un error de firma: `checksums.txt.sig` no corresponde a ese `checksums.txt`.
- Ansible: la tarea que falla lo dice. Un `install.sh` rechazado por la firma o por la suma no instala nada y deja la versión anterior.

## Desinstalar en la flota

- **Quitar Adarve no deshace el hardening**: los cambios aplicados se quedan. Para volver atrás, `adarve rollback <ID>` antes de desinstalar. Con `--purge` / `-Purge` se borran también las instantáneas, y después ya no se puede.
- Windows: retira primero la GPO o la asignación (si no, se reinstala) y después ejecuta `install.ps1 -Uninstall` una vez, con una tarea inmediata o con la asignación *Desinstalar* de Intune.
- Linux: `ansible linux -b -m script -a "scripts/install.sh --uninstall"`.
