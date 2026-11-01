# 06 · Catálogo de controles

Esta página tiene dos partes:

1. **Controles implementados**: se genera automáticamente desde las reglas con `adarve rules doc`. No la edites a mano.
2. **Catálogo objetivo**: los controles previstos para alcanzar la cobertura completa (unos 350 en Windows y 300 en Linux).

Para ver el detalle de un control (descripción, por qué importa, remediación, GPO, comandos, impacto y referencias):

```bash
adarve rules show WIN-CRED-001
```

## 1. Controles implementados

<!-- Generado con "adarve rules doc". No editar a mano: edita las reglas en rules/. -->

**157 controles** en el paquete oficial, **121 con corrección automática** (`adarve harden`). ⚡ = afecta al acceso remoto (requiere `--include-remote`).

### Perfiles

| Perfil | Nombre | Hereda de | Por defecto en |
|---|---|---|---|
| `linux-server-l1` | Linux Servidor · Nivel 1 |  | linux |
| `linux-server-l2` | Linux Servidor · Nivel 2 | linux-server-l1 |  |
| `win-dc-l1` | Controlador de dominio · Nivel 1 | win-server-l1 | windows-dc |
| `win-server-l1` | Windows Server miembro · Nivel 1 |  | windows-member |
| `win-server-l2` | Windows Server miembro · Nivel 2 | win-server-l1 |  |
| `win-workstation-l1` | Windows Estación de trabajo · Nivel 1 |  | windows-client |
| `win-workstation-l2` | Windows Estación de trabajo · Nivel 2 | win-workstation-l1 |  |

### Linux (75)

#### Actualizaciones

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-UPD-001` | Actualizaciones de seguridad automáticas (Debian/Ubuntu) | medio | linux-server-l1 |  | bajo |  |
| `LNX-UPD-002` | Actualizaciones de seguridad automáticas (RHEL) | medio | linux-server-l1 |  | bajo |  |

#### Arranque

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-BOOT-001` | Permisos de la configuración del cargador de arranque | medio | linux-server-l1 | T1542 | ninguno | ✓ |

#### Autenticación

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-AUTH-001` | Solo root tiene UID 0 | crítico | linux-server-l1 | T1136.001, T1078.003 | bajo |  |
| `LNX-AUTH-002` | Sin cuentas con contraseña vacía | crítico | linux-server-l1 | T1078 | bajo |  |
| `LNX-AUTH-003` | Caducidad máxima de contraseñas | bajo | linux-server-l1 |  | bajo | ✓ |
| `LNX-AUTH-004` | Algoritmo de hash de contraseñas robusto | medio | linux-server-l1 | T1110.002 | ninguno | ✓ |
| `LNX-AUTH-005` | umask por defecto restrictiva | bajo | linux-server-l1 |  | bajo | ✓ |
| `LNX-AUTH-006` | sudo usa un pseudo-terminal (use_pty) | medio | linux-server-l1 | T1548.003 | ninguno | ✓ |
| `LNX-AUTH-007` | sudo registra en fichero propio | bajo | linux-server-l1 |  | ninguno | ✓ |
| `LNX-AUTH-008` | sudo exige contraseña (sin NOPASSWD) | medio | linux-server-l2 | T1548.003 | medio |  |
| `LNX-AUTH-009` | sudo-rs no desactiva el pseudo-terminal (use_pty) | medio | linux-server-l1 | T1548.003 | ninguno |  |

#### Control de acceso

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-MAC-001` | Control de acceso obligatorio activo (AppArmor o SELinux) | alto | linux-server-l1 | T1068 | medio |  |

#### Firewall

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-FW-001` | Firewall de host activo | alto | linux-server-l1 | T1021, T1046 | alto |  |

#### Kernel

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-KRN-001` | ASLR completo activado | alto | linux-server-l1 | T1068 | ninguno | ✓ |
| `LNX-KRN-002` | Ocultar direcciones del kernel (kptr_restrict) | medio | linux-server-l1 | T1068 | ninguno | ✓ |
| `LNX-KRN-003` | Restringir dmesg a usuarios privilegiados | medio | linux-server-l1 |  | ninguno | ✓ |
| `LNX-KRN-004` | Restringir ptrace (Yama) | medio | linux-server-l1 | T1055.008 | bajo | ✓ |
| `LNX-KRN-005` | Sin volcados de memoria de binarios setuid | medio | linux-server-l1 |  | ninguno | ✓ |
| `LNX-KRN-006` | Protección de enlaces simbólicos y duros | medio | linux-server-l1 | T1068 | ninguno | ✓ |
| `LNX-KRN-007` | BPF sin privilegios deshabilitado | medio | linux-server-l2 | T1068 | bajo | ✓ |
| `LNX-KRN-008` | Protección de FIFOs y ficheros en directorios compartidos | medio | linux-server-l1 | T1068 | ninguno | ✓ |
| `LNX-KRN-009` | Eventos de rendimiento restringidos (perf_event_paranoid) | medio | linux-server-l1 | T1068 | bajo | ✓ |
| `LNX-KRN-010` | Carga de kernels en caliente deshabilitada (kexec) | bajo | linux-server-l2 | T1014, T1542 | medio | ✓ |
| `LNX-KRN-011` | Carga automática de disciplinas de línea TTY deshabilitada | bajo | linux-server-l2 | T1068 | bajo | ✓ |
| `LNX-KRN-012` | Compilador JIT de BPF reforzado | bajo | linux-server-l2 | T1068 | ninguno | ✓ |
| `LNX-KRN-013` | Teclas SysRq deshabilitadas | bajo | linux-server-l2 | T1529 | bajo | ✓ |

#### Módulos del kernel

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-MOD-001` | Módulo deshabilitado: Sistema de ficheros cramfs | bajo | linux-server-l1 |  | bajo | ✓ |
| `LNX-MOD-002` | Módulo deshabilitado: Sistema de ficheros freevxfs | bajo | linux-server-l1 |  | bajo | ✓ |
| `LNX-MOD-003` | Módulo deshabilitado: Sistema de ficheros HFS | bajo | linux-server-l1 |  | bajo | ✓ |
| `LNX-MOD-004` | Módulo deshabilitado: Sistema de ficheros HFS+ | bajo | linux-server-l1 |  | bajo | ✓ |
| `LNX-MOD-005` | Módulo deshabilitado: Sistema de ficheros JFFS2 | bajo | linux-server-l1 |  | bajo | ✓ |
| `LNX-MOD-006` | Módulo deshabilitado: Almacenamiento USB | medio | linux-server-l1 | T1091, T1052.001 | medio | ✓ |
| `LNX-MOD-007` | Módulo deshabilitado: Protocolo DCCP | medio | linux-server-l2 | T1068 | bajo | ✓ |
| `LNX-MOD-008` | Módulo deshabilitado: Protocolo SCTP | medio | linux-server-l2 | T1068 | bajo | ✓ |
| `LNX-MOD-009` | Módulo deshabilitado: Protocolo RDS | medio | linux-server-l2 | T1068 | bajo | ✓ |
| `LNX-MOD-010` | Módulo deshabilitado: Protocolo TIPC | medio | linux-server-l2 | T1068 | bajo | ✓ |

#### Red

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-NET-001` | Reenvío de paquetes IP deshabilitado | medio | linux-server-l1 |  | medio | ✓ |
| `LNX-NET-002` | No aceptar redirecciones ICMP | medio | linux-server-l1 | T1557 | ninguno | ✓ |
| `LNX-NET-003` | No enviar redirecciones ICMP | medio | linux-server-l1 |  | ninguno | ✓ |
| `LNX-NET-004` | No aceptar paquetes con enrutamiento de origen | medio | linux-server-l1 |  | ninguno | ✓ |
| `LNX-NET-005` | Filtro de ruta inversa (anti-spoofing) | medio | linux-server-l1 |  | medio | ✓ ⚡ |
| `LNX-NET-006` | SYN cookies activadas | medio | linux-server-l1 | T1499 | ninguno | ✓ |
| `LNX-NET-007` | Registrar paquetes marcianos | bajo | linux-server-l1 |  | ninguno | ✓ |
| `LNX-NET-008` | Ignorar ICMP de difusión y respuestas falsas | bajo | linux-server-l1 |  | ninguno | ✓ |
| `LNX-NET-009` | No aceptar anuncios de router IPv6 | medio | linux-server-l2 | T1557 | alto | ✓ ⚡ |

#### Registro y auditoría

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-LOG-001` | auditd instalado y en ejecución | medio | linux-server-l1 |  | ninguno |  |
| `LNX-LOG-002` | journald con almacenamiento persistente | medio | linux-server-l1 | T1070.002 | ninguno |  |

#### SSH

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-SSH-001` | Prohibir el acceso de root por SSH | alto | linux-server-l1 | T1021.004, T1110 | medio | ✓ ⚡ |
| `LNX-SSH-002` | Prohibir contraseñas vacías en SSH | alto | linux-server-l1 | T1078 | ninguno | ✓ |
| `LNX-SSH-003` | Limitar intentos de autenticación SSH | medio | linux-server-l1 | T1110 | bajo | ✓ ⚡ |
| `LNX-SSH-004` | Deshabilitar el reenvío X11 | medio | linux-server-l1 |  | bajo | ✓ |
| `LNX-SSH-005` | Deshabilitar autenticación basada en host (rhosts) | medio | linux-server-l1 |  | ninguno | ✓ |
| `LNX-SSH-006` | Tiempo de gracia de login reducido | bajo | linux-server-l1 |  | ninguno | ✓ |
| `LNX-SSH-007` | Sin cifrados SSH débiles | medio | linux-server-l1 | T1040 | bajo | ✓ ⚡ |
| `LNX-SSH-008` | Sin algoritmos MAC SSH débiles | medio | linux-server-l1 |  | bajo | ✓ ⚡ |
| `LNX-SSH-009` | Sin intercambio de claves SSH débil | medio | linux-server-l1 |  | bajo | ✓ ⚡ |
| `LNX-SSH-010` | Permisos de sshd_config | medio | linux-server-l1 |  | ninguno | ✓ |
| `LNX-SSH-011` | Tiempo de inactividad de sesiones SSH | bajo | linux-server-l1 |  | bajo | ✓ |
| `LNX-SSH-012` | Acceso SSH restringido a usuarios o grupos | medio | linux-server-l1 | T1021.004 | alto |  |
| `LNX-SSH-013` | Solo autenticación por clave en SSH | alto | linux-server-l2 | T1110 | alto | ✓ ⚡ |

#### Servicios

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-SVC-001` | Avahi (mDNS) deshabilitado | medio | linux-server-l1 | T1557 | bajo | ✓ |
| `LNX-SVC-002` | Servidor de impresión CUPS deshabilitado | medio | linux-server-l1 | T1210 | bajo | ✓ |
| `LNX-SVC-003` | rpcbind deshabilitado | medio | linux-server-l1 |  | medio | ✓ |
| `LNX-SVC-004` | Servidor Telnet no instalado | alto | linux-server-l1 | T1040 | bajo |  |
| `LNX-SVC-005` | Servidor FTP no instalado | medio | linux-server-l1 | T1040 | medio |  |
| `LNX-SVC-006` | Sincronización horaria activa | medio | linux-server-l1 |  | ninguno |  |

#### Sistema

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-SYS-001` | Los avisos de inicio de sesión no revelan el sistema | bajo | linux-server-l1 | T1082 | ninguno |  |

#### Sistema de ficheros

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `LNX-FS-001` | /tmp en partición propia con nodev, nosuid y noexec | medio | linux-server-l1 | T1059.004 | medio |  |
| `LNX-FS-002` | /dev/shm con nodev, nosuid y noexec | medio | linux-server-l1 | T1059.004 | bajo |  |
| `LNX-FS-003` | Permisos de /etc/shadow | alto | linux-server-l1 | T1003.008 | ninguno | ✓ |
| `LNX-FS-004` | Permisos de /etc/passwd | alto | linux-server-l1 | T1136.001 | ninguno | ✓ |
| `LNX-FS-005` | Permisos de /etc/gshadow | medio | linux-server-l1 |  | ninguno | ✓ |
| `LNX-FS-006` | Permisos de /etc/crontab | medio | linux-server-l1 | T1053.003 | ninguno | ✓ |
| `LNX-FS-007` | Permisos de los directorios de cron | medio | linux-server-l1 | T1053.003 | ninguno | ✓ |

### Windows y Windows Server (82)

#### Acceso remoto

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-RDP-001` | RDP exige autenticación a nivel de red (NLA) | alto | win-workstation-l1, win-server-l1 | T1021.001, T1210 | bajo | ✓ ⚡ |
| `WIN-RDP-002` | Asistencia remota solicitada deshabilitada | medio | win-workstation-l1, win-server-l1 | T1219 | bajo | ✓ |
| `WIN-RDP-003` | El cliente RDP no guarda contraseñas | medio | win-workstation-l1, win-server-l1 | T1555.004 | bajo | ✓ |
| `WIN-RDP-004` | El servidor RDP pide siempre la contraseña | medio | win-workstation-l1, win-server-l1 | T1021.001 | bajo | ✓ |
| `WIN-RDP-005` | RDP exige comunicación RPC segura | bajo | win-workstation-l1, win-server-l1 | T1021.001 | ninguno | ✓ |
| `WIN-RDP-006` | Cifrado alto en las conexiones RDP | bajo | win-workstation-l1, win-server-l1 | T1021.001, T1557 | bajo | ✓ ⚡ |
| `WIN-WRM-001` | WinRM sin autenticación Basic ni tráfico sin cifrar | medio | win-workstation-l1, win-server-l1 | T1021.006, T1040 | bajo | ✓ |

#### Active Directory

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-DC-001` | Print Spooler deshabilitado en controladores de dominio | crítico | win-dc-l1 | T1187, T1068, T1210 | bajo | ✓ |
| `WIN-DC-002` | Firma LDAP obligatoria | alto | win-dc-l1 | T1557 | alto | ✓ |
| `WIN-DC-003` | Channel binding LDAP activado | alto | win-dc-l1 | T1557 | medio | ✓ |
| `WIN-KRB-001` | Kerberos solo con AES (sin DES ni RC4) | alto | win-workstation-l2, win-server-l2, win-dc-l1 | T1558.003 | alto | ✓ |

#### Auditoría y registro

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-AUD-001` | Auditoría: Creación de procesos | alto | win-workstation-l1, win-server-l1 | T1059, T1204 | ninguno | ✓ |
| `WIN-AUD-002` | Línea de comandos en los eventos de creación de procesos | medio | win-workstation-l1, win-server-l1 | T1059 | ninguno | ✓ |
| `WIN-AUD-003` | Auditoría: Inicio de sesión | medio | win-workstation-l1, win-server-l1 | T1110, T1078 | ninguno | ✓ |
| `WIN-AUD-004` | Auditoría: Validación de credenciales | medio | win-workstation-l1, win-server-l1 | T1110.003 | ninguno | ✓ |
| `WIN-AUD-005` | Auditoría: Administración de grupos de seguridad | medio | win-workstation-l1, win-server-l1 | T1098 | ninguno | ✓ |
| `WIN-AUD-006` | Auditoría: Administración de cuentas de usuario | medio | win-workstation-l1, win-server-l1 | T1136.001, T1098 | ninguno | ✓ |
| `WIN-AUD-007` | Auditoría: Cambio de directiva de auditoría | medio | win-workstation-l1, win-server-l1 | T1562.002 | ninguno | ✓ |
| `WIN-AUD-008` | Auditoría: Inicio de sesión especial | bajo | win-workstation-l1, win-server-l1 | T1078 | ninguno | ✓ |
| `WIN-AUD-009` | Auditoría: Extensión del sistema de seguridad | medio | win-workstation-l1, win-server-l1 | T1543.003 | ninguno | ✓ |
| `WIN-AUD-010` | La auditoría avanzada prevalece sobre la clásica | medio | win-workstation-l1, win-server-l1 |  | ninguno | ✓ |
| `WIN-AUD-011` | Registro de Seguridad de 192 MB o más | medio | win-workstation-l1, win-server-l1 | T1070.001 | ninguno | ✓ |

#### Cifrado

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-ENC-001` | BitLocker protege la unidad del sistema | alto | win-workstation-l1 | T1005, T1003 | bajo |  |
| `WIN-ENC-002` | TLS 1.0 y 1.1 deshabilitados en el servidor | medio | win-workstation-l2, win-server-l1 | T1040, T1557 | medio | ✓ |

#### Credenciales

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-CRED-001` | WDigest no guarda contraseñas en memoria | crítico | win-workstation-l1, win-server-l1 | T1003.001 | ninguno | ✓ |
| `WIN-CRED-002` | LSASS protegido (RunAsPPL) | alto | win-workstation-l1, win-server-l1 | T1003.001 | medio | ✓ |
| `WIN-CRED-003` | Solo NTLMv2 (rechazar LM y NTLMv1) | alto | win-workstation-l1, win-server-l1 | T1557.001, T1110.002 | medio | ✓ |
| `WIN-CRED-004` | No almacenar hashes LM | alto | win-workstation-l1, win-server-l1 | T1110.002 | ninguno | ✓ |
| `WIN-CRED-005` | Sin enumeración anónima de cuentas y recursos | medio | win-workstation-l1, win-server-l1 | T1087.001, T1135 | bajo | ✓ |
| `WIN-CRED-006` | Credential Guard en ejecución | alto | win-workstation-l2, win-server-l2 | T1003.001, T1550.002 | medio |  |
| `WIN-CRED-007` | Limitar credenciales de dominio en caché | medio | win-workstation-l2, win-server-l2 | T1003.005 | medio | ✓ |
| `WIN-CRED-008` | CredSSP solo con equipos actualizados (Encryption Oracle Remediation) | medio | win-workstation-l1, win-server-l1 | T1557, T1210 | bajo | ✓ |

#### Cuentas

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-ACC-001` | Longitud mínima de contraseña de 14 caracteres | alto | win-workstation-l1, win-server-l1 | T1110 | bajo | ✓ |
| `WIN-ACC-002` | Complejidad de contraseñas activada | medio | win-workstation-l1, win-server-l1 | T1110 | ninguno | ✓ |
| `WIN-ACC-003` | Bloqueo de cuenta tras 5 intentos o menos | medio | win-workstation-l1, win-server-l1 | T1110.001 | bajo | ✓ |
| `WIN-ACC-004` | Cuenta de invitado deshabilitada | alto | win-workstation-l1, win-server-l1 | T1078.001 | ninguno | ✓ |
| `WIN-ACC-005` | Contraseñas en blanco solo en consola local | alto | win-workstation-l1, win-server-l1 | T1078 | ninguno | ✓ |
| `WIN-ACC-006` | Contraseña del administrador local gestionada con LAPS | alto | win-workstation-l1, win-server-l1 | T1550.002, T1078.003 | ninguno |  |

#### Defender

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-DEF-001` | Protección en tiempo real activada | crítico | win-workstation-l1, win-server-l1 | T1562.001 | ninguno |  |
| `WIN-DEF-002` | Protección contra alteraciones (Tamper Protection) | alto | win-workstation-l1, win-server-l1 | T1562.001 | ninguno |  |
| `WIN-DEF-003` | Firmas de Defender actualizadas | medio | win-workstation-l1, win-server-l1 |  | ninguno |  |
| `WIN-DEF-004` | Protección en la nube activada | medio | win-workstation-l1, win-server-l1 |  | ninguno | ✓ |
| `WIN-DEF-005` | Bloqueo de aplicaciones potencialmente no deseadas (PUA) | medio | win-workstation-l1, win-server-l1 |  | bajo | ✓ |
| `WIN-DEF-006` | ASR: bloquear el robo de credenciales de LSASS | alto | win-workstation-l1, win-server-l1 | T1003.001 | bajo | ✓ |
| `WIN-DEF-007` | ASR: bloquear procesos hijos de Office | alto | win-workstation-l1 | T1204.002, T1566.001 | medio | ✓ |
| `WIN-DEF-008` | ASR: bloquear contenido ejecutable del correo | alto | win-workstation-l1 | T1566.001 | bajo | ✓ |
| `WIN-DEF-009` | ASR: bloquear controladores firmados vulnerables | alto | win-workstation-l1, win-server-l1 | T1068, T1562.001 | bajo | ✓ |
| `WIN-DEF-010` | ASR: bloquear scripts ofuscados | medio | win-workstation-l2, win-server-l2 | T1027 | medio | ✓ |
| `WIN-DEF-011` | ASR: bloquear persistencia por suscripciones WMI | medio | win-workstation-l2, win-server-l2 | T1546.003 | medio | ✓ |
| `WIN-DEF-012` | Protección de red activada | medio | win-workstation-l2, win-server-l2 | T1071, T1566.002 | bajo | ✓ |
| `WIN-DEF-013` | Sin exclusiones peligrosas en Microsoft Defender | alto | win-workstation-l1, win-server-l1 | T1562.001 | bajo |  |

#### Firewall

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-NET-009` | Firewall activado en los tres perfiles | alto | win-workstation-l1, win-server-l1 | T1021, T1210 | medio |  |
| `WIN-NET-010` | Firewall bloquea las conexiones entrantes por defecto | medio | win-workstation-l1, win-server-l1 |  | medio |  |

#### PowerShell

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-PS-001` | Registro de bloques de script de PowerShell | alto | win-workstation-l1, win-server-l1 | T1059.001 | ninguno | ✓ |
| `WIN-PS-002` | PowerShell 2.0 eliminado | alto | win-workstation-l1, win-server-l1 | T1059.001, T1562.001 | bajo |  |
| `WIN-PS-003` | Registro de módulos de PowerShell | medio | win-workstation-l2, win-server-l2 | T1059.001 | ninguno | ✓ |
| `WIN-PS-004` | Transcripción de PowerShell | bajo | win-workstation-l2, win-server-l2 | T1059.001 | ninguno | ✓ |

#### Red

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-NET-001` | SMBv1 deshabilitado en el servidor SMB | crítico | win-workstation-l1, win-server-l1 | T1210 | medio |  |
| `WIN-NET-002` | Característica SMB 1.0/CIFS desinstalada | medio | win-workstation-l1, win-server-l1 | T1210 | medio |  |
| `WIN-NET-003` | Firma SMB obligatoria en el servidor | alto | win-workstation-l1, win-server-l1 | T1557.001 | bajo |  |
| `WIN-NET-004` | Firma SMB obligatoria en el cliente | medio | win-workstation-l1, win-server-l1 | T1557.001 | bajo |  |
| `WIN-NET-005` | Inicios de sesión de invitado inseguros en SMB deshabilitados | medio | win-workstation-l1, win-server-l1 | T1557 | bajo |  |
| `WIN-NET-006` | LLMNR deshabilitado | alto | win-workstation-l1, win-server-l1 | T1557.001 | bajo | ✓ |
| `WIN-NET-007` | NetBIOS sobre TCP/IP deshabilitado | alto | win-workstation-l1, win-server-l1 | T1557.001 | medio | ✓ |
| `WIN-NET-008` | mDNS deshabilitado | medio | win-workstation-l2, win-server-l2 | T1557 | bajo | ✓ |
| `WIN-NET-011` | Point and Print solo instala controladores como administrador | alto | win-workstation-l1, win-server-l1 | T1068, T1210 | bajo | ✓ |
| `WIN-NET-012` | Controlador cliente SMBv1 deshabilitado | medio | win-workstation-l1, win-server-l1 | T1210 | medio |  |
| `WIN-NET-013` | No aceptar redirecciones ICMP | bajo | win-workstation-l1, win-server-l1 | T1557 | ninguno | ✓ |
| `WIN-NET-014` | Enrutamiento de origen IP deshabilitado | bajo | win-workstation-l1, win-server-l1 | T1599 | ninguno | ✓ |

#### Servicios

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-SVC-001` | Registro remoto deshabilitado | medio | win-workstation-l2, win-server-l2 | T1012, T1112 | bajo | ✓ |

#### Sistema

| ID | Control | Severidad | Perfiles | ATT&CK | Riesgo de rotura | Auto |
|---|---|---|---|---|---|---|
| `WIN-SYS-001` | Control de cuentas de usuario (UAC) activado | alto | win-workstation-l1, win-server-l1 | T1548.002 | bajo | ✓ |
| `WIN-SYS-002` | UAC pide consentimiento a los administradores | medio | win-workstation-l1, win-server-l1 | T1548.002 | bajo | ✓ |
| `WIN-SYS-003` | Arranque seguro (Secure Boot) activado | alto | win-workstation-l1, win-server-l1 | T1542.003 | medio |  |
| `WIN-SYS-004` | AutoRun y AutoPlay deshabilitados | medio | win-workstation-l1, win-server-l1 | T1091 | ninguno | ✓ |
| `WIN-SYS-005` | Integridad de memoria (HVCI) en ejecución | medio | win-workstation-l2, win-server-l2 | T1068, T1014 | medio |  |
| `WIN-SYS-006` | Windows Installer no instala siempre con privilegios elevados | alto | win-workstation-l1, win-server-l1 | T1548 | ninguno | ✓ |
| `WIN-SYS-007` | SmartScreen de Windows activado | medio | win-workstation-l1 | T1204.002 | bajo | ✓ |
| `WIN-SYS-008` | Bloqueo de la sesión tras 15 minutos de inactividad | medio | win-workstation-l1, win-server-l1 | T1078 | bajo | ✓ |
| `WIN-SYS-009` | Protección SEHOP activada | bajo | win-workstation-l1, win-server-l1 | T1203 | ninguno | ✓ |
| `WIN-SYS-010` | Descarga de controladores de impresora por HTTP deshabilitada | bajo | win-workstation-l1, win-server-l1 | T1557 | ninguno | ✓ |
| `WIN-UPD-001` | Actualizaciones automáticas de Windows no desactivadas por directiva | alto | win-workstation-l1, win-server-l1 | T1190, T1203 | bajo | ✓ |
| `WIN-UPD-002` | Servicio Windows Update no deshabilitado | alto | win-workstation-l1, win-server-l1 | T1190, T1203 | bajo |  |

## 2. Catálogo objetivo (🔜)

### Windows 10/11 (unos 350 controles)

| Categoría | Ejemplos pendientes |
|---|---|
| Cuentas | Duración y ventana de bloqueo, renombrar Administrator, contraseñas reversibles, historial |
| Derechos de usuario | `SeDebugPrivilege`, "Access this computer from the network", "Deny log on through RDP" para cuentas locales |
| Credenciales | Restricted Admin / Remote Credential Guard, "Network access: Do not allow storage of passwords" |
| Red | WPAD, firma SMB "si el cliente acepta", cifrado SMB, NTLM saliente |
| Defender | Resto de reglas ASR, protección contra exploits (DEP/ASLR/CFG), Controlled Folder Access |
| Aplicaciones | AppLocker/WDAC, Windows Script Host, Office (macros de Internet, OLE, DDE), Edge/Chrome |
| Cifrado | BitLocker con TPM+PIN, método XTS-AES 256, custodia de la clave de recuperación |
| Sistema | Pantalla de bloqueo (cámara, notificaciones), servicios innecesarios (Xbox, Fax, SSDP…) |

### Windows Server 2016-2025

| Rol | Ejemplos pendientes |
|---|---|
| Miembro | Server Core, roles mínimos, WinRM por HTTPS con JEA, RDP Restricted Admin |
| Controlador de dominio | DSRM, permisos de NTDS, auditoría DS Access, sin navegación web, protección de SYSVOL |
| IIS | TLS 1.2/1.3, cabeceras (HSTS, nosniff), directory browsing, cabecera Server, request filtering |
| Hyper-V, File Server, DNS, RDS | Líneas base específicas por rol |

### Linux

| Categoría | Ejemplos pendientes |
|---|---|
| Sistema de ficheros | `/var/tmp`, `/home` con `nodev`, ficheros sin dueño, escritura global con sticky, SUID/SGID |
| Arranque | Contraseña de GRUB, modo monousuario autenticado, Secure Boot |
| Kernel | `kernel.modules_disabled` (L2), lockdown |
| Autenticación | pam_faillock, pwquality, `TMOUT`, `su` restringido (pam_wheel), cuentas de sistema sin shell |
| Auditoría | Reglas de auditd (identidad, sudoers, hora, módulos, comandos privilegiados), modo inmutable `-e 2`, reenvío rsyslog |
| Integridad | AIDE configurado y programado |
| Servicios | NFS, Samba, SNMP, HTTP/proxy, servidores de correo no necesarios |
| Firewall | Política por defecto `deny` en entrada, loopback, reglas por servicio publicado |
