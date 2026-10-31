# ADR-0005 · Instalador de una línea con verificación SHA-256

**Estado:** aceptada · **Fecha:** 2026-10

## Contexto
La adopción depende de lo fácil que sea probar la herramienta. El patrón `curl | bash` / `irm | iex` es cómodo, pero tiene riesgos conocidos: ejecución de un script truncado y binarios manipulados.

## Decisión
- Un único comando por plataforma que instala, **actualiza** si ya existe, prepara (`adarve init`) y lanza un primer escaneo de solo lectura.
- Bash: todo dentro de `main()`, invocada en la última línea, para que un script truncado no ejecute nada. PowerShell: funciones y llamada final dentro de `try`.
- Verificación **obligatoria** del SHA-256 contra `checksums.txt` antes de extraer. Firma cosign en la fase 1.
- Contrato de releases simple (`latest/download/version.txt`, `download/<tag>/<asset>`) compatible con GitHub y con espejos estáticos internos.
- Nombres de archivo sin versión (`adarve_<os>_<arch>`), para que el instalador y `adarve update` no dependan de la API de GitHub (sin límites de peticiones).
- Alternativas documentadas: revisar el script antes de ejecutarlo, instalación `--local` sin conexión y paquetes nativos (fase 3).

## Consecuencias
- ✅ "Copiar, pegar y listo", también para actualizar.
- ✅ Funciona en redes aisladas con un espejo o un fichero local.
- ⚠️ Mientras no haya firma, la confianza descansa en HTTPS + GitHub. La firma cosign está priorizada en la fase 1.
