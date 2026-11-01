# 09 · Instalación

Un **único comando** instala Adarve, lo actualiza si ya estaba, lo prepara (directorios, configuración y permisos) y lanza un primer escaneo de solo lectura. Para actualizar en el futuro basta con volver a pegarlo, o ejecutar `adarve update`.

## Linux

Requisitos: amd64 o arm64, `curl` o `wget`, `sha256sum` o `shasum`, y root.

```bash
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.sh | sudo bash
```

Con opciones (todo lo que va tras `--` son argumentos del instalador):

```bash
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.sh | sudo bash -s -- --no-scan
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.sh | sudo bash -s -- --version v0.2.0
```

| Opción | Variable | Descripción |
|---|---|---|
| `--version <tag>` | `ADARVE_VERSION` | Versión concreta (por defecto, la última) |
| `--no-scan` | `ADARVE_NO_SCAN=1` | No lanzar el primer escaneo |
| `--force` | | Reinstalar aunque ya esté actualizado |
| `--local <archivo.tar.gz>` | | Instalar sin conexión. Necesita `checksums.txt` y `checksums.txt.sig` de la release en la misma carpeta (se verifican) |
| `--insecure` | | Instalar una release sin firma (anterior a la v0.5) o, con `--local`, aunque falte `checksums.txt`. Una firma inválida se rechaza siempre |
| `--repo <owner/repo>` | `ADARVE_REPO` | Repositorio de GitHub |
| `--releases-url <url>` | `ADARVE_RELEASES_URL` | Espejo interno de releases (`https://`; `http://` solo hacia `127.0.0.1` o `localhost`, para pruebas) |
| `--prefix <dir>` | `ADARVE_PREFIX` | Directorio del binario (por defecto `/usr/local/bin`) |
| `--uninstall [--purge]` | | Desinstalar; `--purge` borra también configuración e informes |

Qué hace, paso a paso:

1. Comprueba que es Linux, que se ejecuta como root y la arquitectura.
2. Consulta la última versión en `<releases>/latest/download/version.txt` y la compara con la instalada.
3. Descarga `checksums.txt` y su firma, **comprueba la firma** con la clave pública que lleva el script (necesita `openssl`), descarga `adarve_linux_<arch>.tar.gz` y **verifica el SHA-256**.
4. Instala `/usr/local/bin/adarve` con reemplazo atómico.
5. Ejecuta `adarve init`: crea `/etc/adarve` (con `config.yaml` y `rules.d/`) y `/var/lib/adarve` (con `reports/` y `snapshots/`) con permisos `0750`.
6. Si `sudo` usa un `secure_path` sin `/usr/local/bin` (RHEL), crea el enlace `/usr/bin/adarve`.
7. Lanza `adarve scan --save` y muestra el resumen y la ruta del informe HTML.

El script completo está dentro de una función `main` que se invoca en la última línea: si la descarga se corta a medias, no se ejecuta nada.

> **¿Prefieres revisar antes de ejecutar?**
> `curl -fsSLO https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.sh && less install.sh && sudo bash install.sh`

## Windows 10/11 y Windows Server 2016-2025

Abre **PowerShell como administrador** y pega:

```powershell
irm https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.ps1 | iex
```

Si no lo abres como administrador, el script pide elevación (UAC) y continúa en una ventana nueva.

Con parámetros:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.ps1))) -NoScan
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.ps1))) -Uninstall -Purge
```

| Parámetro | Variable | Descripción |
|---|---|---|
| `-Version <tag>` | `ADARVE_VERSION` | Versión concreta |
| `-NoScan` | `ADARVE_NO_SCAN=1` | No lanzar el primer escaneo |
| `-NoOpen` | | No abrir el informe HTML al terminar |
| `-Force` | | Reinstalar aunque esté actualizado |
| `-Local <archivo.zip>` | | Instalar sin conexión (necesita `checksums.txt` y `checksums.txt.sig` en la misma carpeta) |
| `-Insecure` | | Instalar una release sin firma (anterior a la v0.5) o, con `-Local`, aunque falte `checksums.txt`. Una firma inválida se rechaza siempre |
| `-Repo <owner/repo>` | `ADARVE_REPO` | Repositorio de GitHub |
| `-ReleasesUrl <url>` | `ADARVE_RELEASES_URL` | Espejo interno (`https://`) |
| `-Uninstall [-Purge]` | | Desinstalar |

Qué hace: activa TLS 1.2 (Windows PowerShell 5.1), detecta la arquitectura (AMD64/ARM64), descarga y verifica `adarve_windows_<arch>.zip`, instala en `C:\Program Files\Adarve\adarve.exe` (renombrando el anterior si está en uso), lo añade al `PATH` del sistema, ejecuta `adarve init` (crea `C:\ProgramData\Adarve` con ACL solo para Administradores y SYSTEM) y lanza `adarve scan --save --open`. Si falla, termina con código 1 (salvo con `irm | iex`, donde solo fija `$LASTEXITCODE` para no cerrar la ventana) y, si no pudo copiar el nuevo `adarve.exe`, recupera el anterior.

Compatible con Windows PowerShell 5.1 y PowerShell 7. Los mensajes evitan símbolos que la consola clásica no puede mostrar.

## Verificar de dónde viene una descarga

El instalador y `adarve update` comprueban solos la firma de la release ([ADR-0009](adr/0009-releases-firmadas.md)). Para comprobarla a mano:

```bash
curl -fsSLO https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/internal/selfupdate/release-signing.pub
openssl dgst -sha256 -verify release-signing.pub -signature checksums.txt.sig checksums.txt
sha256sum -c --ignore-missing checksums.txt
```

Además, cada archivo publicado lleva una atestación de procedencia SLSA firmada en Sigstore con la identidad del workflow de GitHub que lo construyó. Con la CLI de GitHub se comprueba que salió de este repositorio, de su workflow de releases y de una etiqueta concreta:

```bash
gh attestation verify adarve_linux_amd64.tar.gz --repo Ruby570bocadito/adarve
```

```powershell
gh attestation verify adarve_windows_amd64.zip --repo Ruby570bocadito/adarve
```

## Despliegue masivo

Hay ejemplos en [`deploy/`](../deploy), que el CI prueba en máquinas reales. Cómo usarlos y qué hacer cuando algo falla: [17 · Guía de operación](17-guia-de-operacion.md).

| Entorno | Cómo |
|---|---|
| GPO | Script de inicio o tarea inmediata que ejecuta `Deploy-Adarve.ps1 -Version vX.Y.Z` desde un recurso compartido con la release |
| Intune | Aplicación Win32 con esa misma carpeta y `Detect-Adarve.ps1` como regla de detección; Remediations para la postura de cada equipo |
| SCCM | Una aplicación con la misma carpeta, la misma orden de instalación y el mismo script de detección que en Intune |
| Ansible | `deploy/ansible/adarve.yml` en Linux; en Windows, `Deploy-Adarve.ps1` con `win_command` |
| Imágenes doradas | Packer: instalar y ejecutar `adarve scan --min-score 90` como validación |
| 🔜 Paquetes nativos | MSI (WiX), `.deb` y `.rpm` (nfpm) en la fase 3 |

## Redes aisladas y espejos internos

Copia los ficheros de una release a un servidor web interno con esta estructura (la misma que GitHub):

```
https://mirror.interno/adarve/
├── latest/download/version.txt          ← contiene la etiqueta, p. ej. v0.2.0
└── download/v0.2.0/
    ├── checksums.txt
    ├── checksums.txt.sig                ← la firma: sin ella, no se instala
    ├── adarve_linux_amd64.tar.gz
    ├── adarve_linux_arm64.tar.gz
    ├── adarve_windows_amd64.zip
    └── adarve_windows_arm64.zip
```

La firma protege aunque el espejo esté comprometido: quien lo controle puede cambiar los archivos, pero no firmar unas sumas nuevas. Aun así, el espejo debe servirse por **HTTPS**. Adarve y los instaladores rechazan `http://` salvo hacia el propio equipo (`127.0.0.1`, `localhost`), para pruebas.

Úsalo en el instalador (`--releases-url` / `-ReleasesUrl`), en `adarve update --releases-url`, en `config.yaml` o en la variable `ADARVE_RELEASES_URL`. Con privilegios, Adarve ignora `ADARVE_RELEASES_URL`, `ADARVE_REPO` y `ADARVE_HOME` salvo con `--trust-env`: en Windows cualquier programa del usuario puede fijarlas (`HKCU\Environment`) y la consola de administrador las hereda.

```yaml
update:
  releases_url: https://mirror.interno/adarve
```

Sin ningún servidor: copia el archivo, `checksums.txt` y `checksums.txt.sig` a la misma carpeta y usa `--local` / `-Local` (sin ellos se niega; `--insecure` / `-Insecure` lo permite sin verificar).

## Actualizar

```bash
sudo adarve update                    # descarga, verifica y reemplaza
sudo adarve update --check            # solo comprobar
sudo adarve update --version v0.3.2   # una versión concreta (también para volver atrás); avisa si aún no está publicada
sudo adarve update --releases-url https://mirror.interno/adarve/releases   # desde un espejo
```

Las reglas oficiales van dentro del binario: al actualizar Adarve se actualizan también las reglas.

Justo después de publicar una versión, GitHub puede seguir anunciando la anterior como "última" durante unos minutos (caché). `--version` no depende de eso.

En Windows, `C:\Program Files\Adarve` solo lo puede modificar un administrador. Si ejecutas `adarve update` en una ventana normal, Adarve lo detecta antes de descargar nada y abre una ventana de administrador (aviso de UAC) que termina la actualización y espera a que pulses Intro; la ventana original espera a que termine y devuelve su código de salida. El origen (repositorio o espejo) se le pasa en la orden: el proceso elevado no hereda las variables de la consola. En Linux, sin root, te pide repetir con `sudo`.

## Rutas

| | Linux | Windows |
|---|---|---|
| Binario | `/usr/local/bin/adarve` | `C:\Program Files\Adarve\adarve.exe` |
| Configuración | `/etc/adarve/config.yaml` | `C:\ProgramData\Adarve\config.yaml` |
| Reglas propias | `/etc/adarve/rules.d/` | `C:\ProgramData\Adarve\rules.d\` |
| Informes | `/var/lib/adarve/reports/` | `C:\ProgramData\Adarve\reports\` |
| Instantáneas de `harden` | `/var/lib/adarve/snapshots/` | `C:\ProgramData\Adarve\snapshots\` |

`ADARVE_HOME` sustituye la configuración y los datos por un único directorio (útil en desarrollo). Con privilegios solo se usa con `--trust-env`.

### Desde Bastion

Adarve se llamaba antes Bastion. Al volver a ejecutar el instalador:

- Las carpetas de Bastion (`/etc/bastion`, `/var/lib/bastion`, `C:\ProgramData\Bastion` y la de informes del usuario) se trasladan a las de Adarve la primera vez que se usan, con sus permisos. Si no se pueden trasladar (sin privilegios o con ficheros en uso), Adarve sigue usando las antiguas.
- La ronda diaria de Bastion se retira y se programa la de Adarve a la misma hora.
- Se borran el ejecutable antiguo y su entrada en el `PATH`.
- Los informes, análisis de superficie y excepciones guardados con el formato de Bastion se siguen leyendo, y las variables `BASTION_*` se siguen aceptando.
- Los ficheros que `harden` crea en el sistema conservan el nombre de Bastion (por ejemplo `/etc/sysctl.d/99-zz-bastion.conf`), así que `adarve rollback` deshace también los cambios aplicados con Bastion.

Con privilegios, Adarve comprueba que solo los administradores (o root) puedan modificar la carpeta de configuración, `config.yaml`, `exceptions.yaml` y `rules.d`. Si no es así (por ejemplo, porque otro usuario creó la carpeta antes), ignora esos ficheros y avisa; los comandos que escriben (y `adarve init`) apartan los ficheros no fiables como `*.no-confiable-<fecha>` y restablecen los permisos.

## Desinstalar

```bash
curl -fsSL https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.sh | sudo bash -s -- --uninstall [--purge]
```

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/Ruby570bocadito/adarve/main/scripts/install.ps1))) -Uninstall [-Purge]
```

Quita el binario, el `PATH` y el análisis programado (la tarea `\Adarve\Escaneo diario` y el origen Adarve del Visor de eventos, o el temporizador de systemd o la entrada de cron). La configuración y los informes se conservan salvo con `--purge` / `-Purge`.
