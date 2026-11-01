# 12 · Pruebas y laboratorio

Una herramienta de hardening solo es creíble si sus resultados son correctos. Un falso "superado" es peor que no tener herramienta.

## Niveles de prueba

| Nivel | Qué cubre | Dónde | Estado |
|---|---|---|---|
| Unitarias del motor | Operadores, `default`/`on_missing`, `each`, compuestas `all`/`any`, puntuación | `internal/engine/engine_test.go` | ✅ |
| Parsers | `sshd_config` (Include, Match, tiempos), `sshd -T`, mountinfo, modprobe.d, clave/valor, INF de secedit, CSV de auditpol, UTF-16, rutas de registro | `internal/probes/parse_test.go` | ✅ |
| Paquete de reglas | Todas las reglas y perfiles válidos, cada perfil por defecto con reglas, herencia del DC | `rules/rules_test.go` | ✅ |
| Actualización | Comparación de versiones, `checksums.txt`, espejo simulado, **rechazo de archivo manipulado, de sumas sin firma y de firma inválida**, firma real de `openssl` y la misma clave en los instaladores | `internal/selfupdate/selfupdate_test.go` | ✅ |
| Hardening (motor) | Plan por olas, aplicación, fallo con reversión, cambio sin efecto con reversión, rollback desde disco, acceso remoto no confirmado, dead-man switch, GPO, validación de acciones (incluidos intentos de inyección) | `internal/remediate/plan_test.go` | ✅ |
| Remediadores Linux | Ciclo capturar → aplicar → restaurar en un sistema de ficheros simulado (sysctl, login.defs, permisos, modprobe, sudoers con `visudo` real) | `internal/remediate/linux_test.go` | ✅ |
| Ciclo real en CI | `harden --apply` en Ubuntu y Windows Server de GitHub: la postura debe subir y, tras `rollback`, volver exactamente al valor inicial | `.github/workflows/ci.yml` | ✅ |
| Escaneo real en CI | `adarve scan` en Ubuntu 24.04, Ubuntu 26.04 (sudo-rs por defecto) y Windows Server de GitHub Actions; informes como artefacto | `.github/workflows/ci.yml` | ✅ |
| Instaladores | ShellCheck, PSScriptAnalyzer | CI | ✅ |
| Fuzzing | 14 parsers de la salida del sistema auditado: ninguna entrada debe hacer caer a Adarve | `internal/surface/fuzz_test.go`, `internal/probes/fuzz_test.go`; cada noche en `.github/workflows/fuzz.yml` | ✅ |
| Análisis estático | `govulncheck`, `staticcheck` y `gosec` (Linux y Windows) | CI, job «Análisis de seguridad» | ✅ |
| Permisos como root | La carpeta de datos se restringe sin seguir enlaces simbólicos | `internal/config/perms_unix_test.go` con `sudo` en CI | ✅ |
| Instaladores de punta a punta | Migración desde Bastion (datos, configuración, binario, PATH y ronda diaria a la misma hora), reinstalación, `update`, releases manipuladas y sin firma (también con `--insecure`), `--local` con y sin firma, desinstalación con y sin `--purge`, en Ubuntu y Windows reales contra un espejo firmado con una clave de prueba | `scripts/e2e/`, job «Instaladores de punta a punta» | ✅ CI |
| Despliegue de punta a punta | El playbook de Ansible contra el propio runner (versión fija, `changed=0` al repetirlo, cambio de hora y de versión, releases manipuladas y sin firma, puntuación mínima) y `Deploy-Adarve.ps1` desde PowerShell de 64 y de 32 bits con los scripts de Intune (detección, Remediations con la ola 1 y su rollback) | `scripts/e2e/deploy-*`, job «Despliegue de ejemplo» | ✅ CI |
| Fixtures por regla | Cada regla con un caso que pasa y otro que falla sobre un sistema simulado | `adarve rules test` | 🔜 fase 2 |
| Laboratorio de VMs | Ciclo `scan → harden → verify → rollback → verify` + idempotencia | Packer/Vagrant | 🔜 fase 2 |
| Validación cruzada | Comparar resultados con CIS-CAT Lite, OpenSCAP y HardeningKitty | Laboratorio | 🔜 |

## Ejecutar

```bash
make test                      # todo
go test ./internal/engine/ -v  # un paquete
go test -race ./...            # detector de carreras (el motor es concurrente)
```

## Probar los instaladores con un espejo local

```bash
# 1. Construir dos "releases"
for v in 0.1.0 0.2.0; do
  mkdir -p /tmp/m/download/v$v /tmp/b$v
  go build -ldflags "-X github.com/Ruby570bocadito/adarve/internal/version.Version=$v" -o /tmp/b$v/adarve ./cmd/adarve
  tar -C /tmp/b$v -czf /tmp/m/download/v$v/adarve_linux_amd64.tar.gz adarve
  (cd /tmp/m/download/v$v && sha256sum adarve_* > checksums.txt)
done
mkdir -p /tmp/m/latest/download && echo v0.1.0 > /tmp/m/latest/download/version.txt

# 2. Servir el espejo
(cd /tmp/m && python3 -m http.server 8765 &)

# 3. Instalar como lo haría un usuario
export ADARVE_RELEASES_URL=http://127.0.0.1:8765 ADARVE_HOME=/tmp/bh
cat scripts/install.sh | sudo -E bash -s -- --prefix /tmp/bin
# (adarve, ejecutado como root por el instalador, ignora ADARVE_HOME sin
#  --trust-env: el init y el primer escaneo usan /etc/adarve y /var/lib/adarve)

# 4. Publicar v0.2.0 y probar la actualización (one-liner y adarve update)
echo v0.2.0 > /tmp/m/latest/download/version.txt
sudo -E /tmp/bin/adarve --trust-env update   # o: update --releases-url http://127.0.0.1:8765
```

Escenarios verificados: instalación limpia con primer escaneo, reejecución sin cambios, actualización con el one-liner, auto-actualización con `adarve update`, **archivo manipulado rechazado** (en ambos caminos) y desinstalación.

## Laboratorio de máquinas virtuales (🔜 fase 2)

| Imagen | Rol |
|---|---|
| Windows 11 24H2 / 25H2 | Estación de trabajo (local y unida a dominio) |
| Windows Server 2019, 2022, 2025 | Servidor miembro y **controlador de dominio** |
| Ubuntu 22.04 / 24.04 | Servidor |
| Debian 12 / 13 | Servidor |
| Rocky / Alma 9 | Servidor con SELinux |

Construidas con Packer (imágenes base) y orquestadas con Vagrant o Proxmox. Pipeline nocturno:

1. Escaneo de la imagen limpia: resultado de referencia (*golden*).
2. `harden --wave 1..3`: todas las reglas aplicables deben pasar.
3. *Health checks*: RDP/SSH, dominio y servicios.
4. `rollback`: el escaneo debe volver a ser idéntico al de referencia.
5. `harden` dos veces: el segundo no debe cambiar nada (idempotencia).
