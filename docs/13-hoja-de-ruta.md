# 13 · Hoja de ruta

Adarve está **terminado** cuando cumple esta frase:

> Un auditor o un administrador lleva el binario en un USB, audita Windows 11,
> Windows Server 2022 y Ubuntu 24.04, los endurece con rollback y entrega un
> informe defendible, sin falsos positivos conocidos, con una release firmada.

Eso es la **v1.0**: la mejor herramienta para **un equipo**. Todo lo que no
sirve a esa frase va a [1.x](#después-de-la-v10-1x) o a la
[visión a largo plazo](15-vision-a-largo-plazo.md) (flota, defensa,
enterprise), y no cuenta para decir que el proyecto está completo.

## Lo que ya está hecho

- **Motor y reglas:** 157 controles reales para Windows 10/11, Windows Server 2016-2025 (miembro y DC) y Linux, perfiles por rol con niveles L1/L2, 19 operadores y reglas declarativas sin ejecución arbitraria.
- **La ronda (`scan`):** solo lectura, puntuación ponderada, evidencias, excepciones con caducidad, MITRE ATT&CK, informe HTML autocontenido y JSON estable.
- **Reparar (`harden`):** 100 controles automáticos con simulación, instantánea, verificación, rollback automático, olas por riesgo de rotura y dead-man switch para SSH/RDP.
- **Las puertas (`surface`):** puertos con proceso y origen del binario, firewall de Windows y de Linux (nftables e iptables), servicios de riesgo, recursos compartidos, administradores, cambios entre análisis y `surface fix` en Windows.
- **La ronda diaria (`schedule`):** Programador de tareas, systemd o cron, con avisos en el Visor de eventos, syslog o webhook.
- **La consola (`ui`):** la muralla, la simulación de olas, las puertas, las rondas y las excepciones, solo en 127.0.0.1 y con token.
- **Distribución:** instaladores de una línea, actualización verificada, espejos internos, CI en Linux y Windows, GoReleaser y SBOM.

## v1.0 · Lo que falta

Doce tareas en cuatro bloques. Cuando estén todas marcadas, se publica la v1.0.

### Identidad

- [x] Consola con la identidad de Adarve: muralla, puertas y voz.
- [ ] Renombrado de Bastion a Adarve con migración de las instalaciones existentes (hecho en el código) y repositorio renombrado en GitHub (pendiente).
- [x] Informes HTML con la misma identidad.
- [x] README con capturas nuevas y un GIF de la muralla simulando las olas, generados con datos de demostración (`scripts/demo`).

### Confianza

- [x] Releases firmadas, verificadas en `adarve update`, `install.sh` e `install.ps1`, más la atestación de procedencia de GitHub ([ADR-0009](adr/0009-releases-firmadas.md)).
- [x] CI con `govulncheck`, `staticcheck` y `gosec`, y *fuzzing* (`go test -fuzz`) de 14 parsers de la salida del sistema auditado.
- [x] Prueba de punta a punta de los instaladores en CI contra un espejo local firmado: instalar, migrar desde Bastion, actualizar, rechazar releases manipuladas o sin firma, `--local` y desinstalar (`scripts/e2e/`).

### Precisión

- [ ] Laboratorio en CI con Windows 11, Windows Server 2022 y Ubuntu 24.04: cada informe se compara con un resultado esperado (*golden files*) y no queda ningún falso positivo conocido.
- [ ] Estado `manual` para los controles que necesitan revisión humana, fuera de la puntuación.
- [x] sudo-rs (Ubuntu 25.10 en adelante): se detecta la implementación (ruta y `sudo --version`); LNX-AUTH-007 (`logfile`) y LNX-AUTH-006 (`use_pty` explícito) solo aplican al sudo clásico y LNX-AUTH-009 vigila que nadie desactive `use_pty` en sudo-rs; la remediación no escribe en sudoers opciones que sudo-rs no admite. El CI prueba en Ubuntu 24.04 y 26.04.

### Estabilidad

- [x] Esquemas `adarve.report/v1`, `adarve.surface/v1`, `adarve.notify/v1`, `adarve.exceptions/v1`, `adarve.change/v1`, `config.yaml` y formato de reglas congelados, con una política de compatibilidad escrita ([16](16-formatos-y-compatibilidad.md), [ADR-0010](adr/0010-formatos-estables.md)) y tests que la hacen cumplir.
- [ ] Guía de operación: qué hacer si un rollback falla y cómo desplegar Adarve por GPO, Intune o Ansible.

## Después de la v1.0 (1.x)

Mejoras que hacen Adarve más completo, pero que no hacen falta para cumplir la frase de arriba. Se ordenan cuando la v1.0 esté publicada.

**Más alcance**
- `surface fix` en Linux (ufw, firewalld y nftables) con el mismo ciclo instantánea → verificación → rollback → dead-man.
- Ampliar el catálogo hacia unas 350 reglas de Windows y 300 de Linux, priorizando CIS L1 de Windows 11, Server 2022 y Ubuntu 24.04 ([catálogo objetivo](06-catalogo-de-controles.md#2-catálogo-objetivo-)).
- Laboratorio ampliado: Server 2022 como DC, Debian 12, RHEL 9, Alpine y Ubuntu 22.04/26.04.
- Mapeo verificado a CIS, STIG y ENS por versión de benchmark ([14](14-marcos-y-licencias.md)).

**Más precisión**
- Probes `rsop`/`gpo` (quién gestiona cada valor) e Intune/MDM, para sustituir la heurística por ruta de directiva.
- Probes `userrights` (SIDs legibles), `auditd_rules` y `pam`.
- `surface`: integridad de los paquetes de los binarios a la escucha (`dpkg --verify`, `rpm -V`), y cadenas de prerouting/ingress y *Windows Service Hardening* evaluadas, no solo anotadas.

**Más herramientas para quien escribe reglas o despliega**
- *Health checks* tras aplicar (un puerto responde, un servicio sigue activo, un login SSH funciona).
- `adarve rules new|test` con fixtures y un probe simulado, para escribir reglas sin una máquina real.
- `studio`: perfiles propios y exportación a GPO, Ansible, DSC y scripts.
- Paquetes nativos: MSI firmado, `.deb` y `.rpm` con repositorio; firma Authenticode de `adarve.exe`.

**Más robustez**
- Test de concurrencia real entre el proceso de `harden` y el dead-man (dos procesos, no goroutines) en Linux y Windows.
- Cerrar la ventana residual al retirar un bloqueo abandonado entre dos procesos (`flock` / `LockFileEx`).
- Auditoría de seguridad externa del binario y de la consola local.

## Más adelante

Flota (agente y servidor), defensa (`telemetry`, `hunt`, `lockdown`, `vuln`) y enterprise (`ad`, anillos de despliegue, SSO, integraciones): ver [15 · Visión a largo plazo](15-vision-a-largo-plazo.md). La flota reutiliza `schedule`, `notify` y los esquemas JSON congelados, así que no empieza hasta que la v1.0 esté publicada.
