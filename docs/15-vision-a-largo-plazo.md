# 15 · Visión a largo plazo

> Esto **no** forma parte de la v1.0. Es hacia dónde puede crecer Adarve
> cuando la herramienta para un equipo esté terminada (ver la
> [hoja de ruta](13-hoja-de-ruta.md)). Nada de esta página cuenta para
> decir que el proyecto está completo.

Adarve 1.0 audita, endurece y vigila **un equipo**. A partir de ahí, la
misma base (motor, reglas, `schedule`, `notify` y los esquemas JSON
congelados) permite crecer hacia una plataforma de flota. Ese crecimiento es
otro producto y empieza solo cuando la v1.0 esté publicada y estable.

El detalle de cada herramienta está en [03 · Suite de herramientas](03-herramientas.md).

## Fase 3 · Flota 🔜

- [ ] `adarve agent` (servicio de Windows / systemd), alta con token y mTLS.
- [ ] `adarve-server` (Go + PostgreSQL), API REST y gRPC.
- [ ] Consola web (React) con dashboard, activos, detalle, políticas, informes e historial.
- [x] `schedule`: análisis diario programado (Programador de tareas, systemd o cron) con aviso de cambios en la exposición: Visor de eventos o syslog y webhook (ntfy, Slack, Discord, Teams, JSON).
- [ ] `guard` (desviaciones en tiempo real) y `observe` (auditar antes de aplicar).
- [ ] Excepciones con caducidad; RBAC; SSO/OIDC; MFA; aprobación a cuatro ojos.
- [ ] Paquetes nativos: MSI, `.deb` y `.rpm`.

## Fase 4 · Defensa 🔜

- [ ] `telemetry`: baseline de logging, Sysmon/auditd gestionados, eventos canario contra el SIEM.
- [ ] `hunt`: persistencia, integridad, credenciales expuestas, diferencias entre escaneos.
- [ ] `lockdown`: contención con TTL y evidencias.
- [ ] `vuln`: inventario, parches, OSV/NVD/MSRC, KEV y EPSS.
- [ ] Mapa ATT&CK de detección.

## Fase 5 · Enterprise 🔜

- [ ] `ad`: auditoría de Active Directory y AD CS.
- [ ] Anillos de despliegue con *health gates*.
- [ ] Integraciones SIEM/ITSM, webhooks.
- [ ] Informes por marco (PDF), marca blanca, multi-cliente (MSSP).
- [ ] Copiloto IA opcional y grafo de rutas de ataque.
