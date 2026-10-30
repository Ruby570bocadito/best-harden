# 11 · Desarrollo

## Entorno

- **Go** (la versión de `go.mod`; con `GOTOOLCHAIN=auto`, Go descarga la versión correcta).
- `make`, `git`. Opcional: ShellCheck, PowerShell 7 con PSScriptAnalyzer y GoReleaser.
- Para probar en Windows desde Linux: `GOOS=windows go build ./cmd/bastion` y copiar el `.exe` a una VM.

```bash
git clone https://github.com/Ruby570bocadito/bastion && cd bastion
make help
make build && sudo ./bin/bastion scan
```

| Objetivo | Acción |
|---|---|
| `make build` | Compila `bin/bastion` con versión y commit |
| `make test` | Tests |
| `make lint` | gofmt + `go vet` para Linux **y** Windows |
| `make rules-lint` | Valida el paquete de reglas |
| `make cross` | Compila linux/windows × amd64/arm64 en `dist/` |
| `make report` | Escanea y abre el informe |
| `make set-repo REPO=usuario/bastion` | Cambia el repositorio de ejemplo en todo el proyecto |

Desarrollar sin tocar `/etc` ni `/var/lib`:

```bash
export BASTION_HOME=$PWD/.dev
go run ./cmd/bastion init && sudo -E go run ./cmd/bastion --trust-env scan --save
# Con privilegios, BASTION_HOME (y BASTION_RELEASES_URL, BASTION_REPO) solo se
# usan con --trust-env: cualquier programa del usuario podría fijarlas.
```

## Estructura y responsabilidades

Ver [02-arquitectura.md](02-arquitectura.md#estructura-del-repositorio). Reglas de dependencia:

- `pkg/rule` no depende de nada interno: es el contrato público.
- `internal/probes` no conoce reglas ni motor: recibe parámetros y devuelve observaciones.
- `internal/engine` une reglas y probes; no imprime nada.
- `internal/report` solo presenta; `internal/cli` orquesta.
- El código específico de cada SO lleva *build tags* (`//go:build linux` / `windows`). Los **parsers son puros y sin tags** (`parse_*_formats.go`) para probarlos en cualquier plataforma.

## Añadir una regla

1. Elige el fichero por plataforma y categoría en `rules/linux/` o `rules/windows/`.
2. Escribe la regla siguiendo la [guía de estilo](04-motor-de-reglas.md#guía-de-estilo-para-escribir-reglas). Para validación en el editor, añade arriba:
   `# yaml-language-server: $schema=../schema/rule.schema.json`
3. `make rules-lint test`.
4. Pruébala en un equipo real: `sudo ./bin/bastion scan --rule TU-ID -a`.
5. Regenera el catálogo: `./bin/bastion rules doc > /tmp/c.md` y actualiza la sección 1 de `docs/06-catalogo-de-controles.md`.

## Añadir un probe

1. Implementa la interfaz en `internal/probes`:

   ```go
   type Probe interface {
       Name() string
       DefaultField() string
       Collect(ctx context.Context, p Params) (Observation, error)
   }
   ```

2. Regístralo en el `init()` del fichero de su plataforma y añádelo a `probes.Known` (lo usa el linter) y al enum de `rules/schema/rule.schema.json`.
3. Normas obligatorias:
   - **Solo lectura.** Nunca modifica el sistema.
   - **Comandos fijos.** Nunca construyas un comando con texto de la regla. En Windows usa `sys32()` para la ruta absoluta.
   - Devuelve `Found: false` si el objeto no existe y `NotApplicable(...)` si el control no tiene sentido en el equipo.
   - Si es caro, usa `cached(ctx, clave, fn)` para ejecutarlo una sola vez por escaneo.
   - Separa el parser en una función pura con su test.
4. Documenta parámetros y campos en [04-motor-de-reglas.md](04-motor-de-reglas.md#probes).

## Convenciones

- Código, identificadores y comentarios técnicos: Go idiomático. Mensajes de usuario y documentación: **español**.
- Commits: `tipo(área): descripción` (`feat`, `fix`, `docs`, `rules`, `test`, `chore`).
- Toda regla nueva o modificada pasa `rules lint` en CI. Todo probe nuevo tiene test de su parser.

## Publicar una release

1. Actualiza el changelog si procede y crea la etiqueta: `git tag v0.2.0 && git push origin v0.2.0`.
2. El workflow `release.yml`:
   - genera `.release/version.txt` con la etiqueta (lo usan los instaladores);
   - ejecuta GoReleaser: tests, binarios para 4 plataformas, `bastion_<os>_<arch>.tar.gz|zip`, `checksums.txt`, SBOM, y adjunta `install.sh` e `install.ps1`.
3. Comprueba la instalación con el one-liner en una VM limpia de cada plataforma.

> El nombre de los archivos **no lleva versión** (`bastion_linux_amd64.tar.gz`): los instaladores y `bastion update` lo construyen a partir del sistema y la arquitectura.
