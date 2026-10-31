# 02 · Arquitectura

## Visión general

Adarve tiene dos modos de uso que comparten el **mismo motor**:

```
 MODO STANDALONE (✅ hoy)                     MODO FLOTA (🔜 fase 3)
 ─────────────────────────                    ──────────────────────
 adarve scan / rules / update                Agentes en cada equipo
 informe HTML/JSON local                      ──► Servidor central
 binario único, sin dependencias              ──► Consola web
 Para: administradores, consultores,          Para: SOC, sistemas, MSSP
 auditores, redes aisladas, CI/CD
```

```
                ┌───────────────────────────────────────────────┐
                │            UI web (React) · fase 3             │
                │ Dashboard · Activos · Políticas · Hardening ·  │
                │ Defensa · Informes · Excepciones · Ajustes     │
                └───────────────────────┬───────────────────────┘
                                        │ HTTPS · REST + WebSocket
                                        │ OIDC/SSO + MFA + RBAC
                ┌───────────────────────▼───────────────────────┐
                │              Adarve Server (Go)               │
                │  API · Fleet · Compliance · Jobs/Approvals ·   │
                │  Rule Pack Registry · Reports · Audit Log      │
                └───────┬──────────────────────────┬────────────┘
                        │                          │ gRPC + mTLS
              ┌─────────▼────────┐                 │ (el agente inicia la conexión;
              │ PostgreSQL +     │                 │  los equipos no abren puertos)
              │ almacén evidencias│                │
              └──────────────────┘      ┌──────────┼──────────┐
                                        ▼          ▼          ▼
                                    Win 10/11   WinSrv/DC    Linux
                                    (agente = el mismo binario adarve)
```

## El binario `adarve` (✅)

Un único ejecutable estático (Go, `CGO_ENABLED=0`) para Linux y Windows en amd64/arm64. Contiene la CLI, el motor y el **paquete oficial de reglas incrustado** (`go:embed`). Al actualizar el binario se actualizan las reglas.

```
adarve
├── CLI (cobra) ─────────── scan · info · rules · profiles · update · init · version
├── platform ────────────── detecta SO, rol (estación/servidor/DC), dominio, etiquetas
├── rule (pkg/rule) ─────── formato de reglas y perfiles, carga, validación, selección
├── engine ──────────────── evaluación paralela, operadores, compuestas, puntuación
├── probes ──────────────── recolectores de SOLO LECTURA
│   ├── comunes:  file_content · file_regex · file_kv
│   ├── linux:    sysctl · file · sshd · kmod · systemd · mount · package
│   └── windows:  registry · secpol · auditpol · service · ps (consultas fijas)
├── report ──────────────── consola · JSON (adarve.report/v1) · HTML autocontenido
├── selfupdate ──────────── releases firmadas y verificadas, reemplazo atómico
└── config ──────────────── rutas, config.yaml, permisos de los directorios
```

### Flujo de un escaneo

```
platform.Detect() ──► etiquetas del equipo (p. ej. windows-dc, windows-server, windows)
        │
        ▼
Catalog.Load(reglas oficiales + rules.d) ──► Validate()
        │
        ▼
Perfil (pedido o por defecto según el rol) ──► Catalog.Select(etiquetas, perfil + ancestros)
        │
        ▼
engine.Run(reglas) ── N workers ──► probe.Collect() ──► comparar (op, expected, default…)
        │                    └── Session: caché por escaneo (un solo secedit, sshd -T…)
        ▼
ComputeScore() ──► Report ──► consola · JSON · HTML
```

### Decisiones clave del motor

- **Reglas declarativas (YAML).** Una regla describe *qué* leer y *qué* esperar; no contiene código. Ver [04-motor-de-reglas.md](04-motor-de-reglas.md).
- **Probes de solo lectura con comandos fijos.** Un probe solo ejecuta comandos definidos en el código (`secedit`, `auditpol`, `sshd -T`, `systemctl show`...) con ruta absoluta en Windows. El probe `ps` solo admite consultas PowerShell de una **lista blanca**; la regla elige una por nombre.
- **Valor efectivo, no solo el fichero.** `sshd -T` en vez de leer `sshd_config`, `sysctl` en ejecución, firewall con `-PolicyStore ActiveStore`, auditoría con `auditpol /backup` (valores numéricos independientes del idioma).
- **Caché por escaneo (`probes.Session`).** Las operaciones caras se ejecutan una sola vez aunque las pidan 20 reglas en paralelo.
- **Estados honestos.** `pass`, `fail`, `error` (no se pudo leer), `skipped` (sin evaluar por falta de privilegios), `exception` (falla, pero con una excepción vigente), `na` (no aplica). Un error o un control sin evaluar nunca se convierte en "superado".
- **Tolerancia a fallos.** Un pánico dentro de un probe se convierte en `error` de esa regla; el escaneo continúa.

### Puntuación

```
puntuación = Σ peso(superados) / Σ peso(superados + fallidos) × 100
peso: crítico 10 · alto 5 · medio 3 · bajo 1 · info 0
```

Los `error`, `skipped`, `exception` y `na` no cuentan. Si hay errores o controles sin evaluar, la puntuación se marca como **parcial**. Calificación: A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60.

## Estructura del repositorio

```
adarve/
├── cmd/adarve/            punto de entrada
├── internal/
│   ├── cli/                comandos
│   ├── config/             rutas y config.yaml (+ permisos por SO)
│   ├── engine/             evaluación, operadores, puntuación, excepciones
│   ├── exceptions/         exceptions.yaml (riesgo aceptado con caducidad)
│   ├── platform/           detección de plataforma (linux/windows)
│   ├── probes/             recolectores (+ parsers puros con tests)
│   ├── remediate/          harden: acciones tipadas, plan, instantáneas, rollback
│   ├── report/             consola, JSON, HTML (assets/report.html), historial
│   ├── selfupdate/         actualización verificada
│   ├── ui/                 consola local "adarve ui" (assets/ui.html)
│   └── version/            versión inyectada con -ldflags
├── pkg/rule/               formato público de reglas y perfiles
├── rules/                  paquete oficial (incrustado en el binario)
│   ├── linux/  windows/  profiles/  schema/rule.schema.json
├── scripts/                install.sh · install.ps1 · set-repo.sh
├── docs/                   esta documentación
├── .github/workflows/      CI (Linux + Windows) y release
├── .goreleaser.yaml        compilación y publicación de releases
└── Makefile
```

Cuando llegue el modo flota se añadirán `cmd/adarve-server/`, `internal/server/...`, `proto/` (contratos gRPC) y `web/` (consola de flota en React).

## Modo flota (🔜 fase 3)

| Componente | Tecnología | Notas |
|---|---|---|
| Agente | El mismo binario `adarve agent` | Servicio de Windows / unidad systemd; conexión saliente |
| Transporte | gRPC (Connect) + mTLS | Alta con token de un solo uso, rotación de certificados |
| Servidor | Go + PostgreSQL | API REST (OpenAPI) para la UI, gRPC para los agentes |
| Evidencias | Almacén de objetos (S3 compatible / disco) | Informes JSON, paquetes de evidencias firmados |
| UI | React + TypeScript + Vite + Tailwind + shadcn/ui + TanStack + ECharts | Ver [07-ui-y-diseno.md](07-ui-y-diseno.md) |
| Auth | OIDC/SSO, MFA, RBAC (Admin, Operador, Auditor, Respuesta a incidentes) | |
| Auditoría | Log con cadena de hashes (a prueba de manipulación) | |

### Modelo de datos (borrador)

```
Organization ─┬─ Asset (host) ── Agent (cert, versión, último contacto)
              │        └── Scan ── Result (rule_id, status, evidence, actual, expected)
              ├─ RulePack (versión, firma) ── Rule
              ├─ Profile (herencia, parámetros, overrides por etiqueta)
              ├─ Exception (regla, alcance, motivo, responsable, caducidad)
              ├─ RemediationJob (plan, aprobaciones, anillo, estado, snapshot)
              ├─ User / Role
              └─ AuditLog (encadenado por hash)
```

### Contrato agente ↔ servidor (borrador)

- `Enroll(token, csr) → cert`
- `Heartbeat(inventory) → pending_jobs[]`
- `SubmitScan(report adarve.report/v1)`
- `GetRulePack(version) → paquete firmado`
- `ReportJob(job_id, status, evidence)`

El servidor **nunca** envía comandos arbitrarios: solo trabajos tipados (escanear con un perfil o aplicar un plan aprobado de un paquete firmado). Ver [ADR-0004](adr/0004-sin-ejecucion-arbitraria.md).
