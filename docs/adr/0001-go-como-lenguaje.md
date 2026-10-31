# ADR-0001 · Go como lenguaje del agente y del servidor

**Estado:** aceptada · **Fecha:** 2026-10

## Contexto
El agente debe ejecutarse en Windows 10/11, Windows Server 2016-2025 y varias distribuciones Linux, en amd64 y arm64, sin instalar dependencias y con privilegios elevados. El servidor (fase 3) debe compartir modelos con el agente.

## Opciones
- **Go**: binario estático único, compilación cruzada trivial, acceso nativo al registro, servicios y WMI (`golang.org/x/sys/windows`), concurrencia sencilla, ecosistema de seguridad maduro (osquery-like, Teleport, Vault).
- **Rust**: más garantías de memoria y binarios más pequeños, pero menor velocidad de desarrollo y API de Windows más verbosa.
- **Python / PowerShell + Bash**: rápido de prototipar, pero exige intérprete, es frágil entre versiones y obliga a mantener dos bases de código.

## Decisión
Go para el agente/CLI y para el servidor, sin CGO.

## Consecuencias
- ✅ Un único binario de unos 4 MB por plataforma, sin dependencias.
- ✅ Modelos compartidos (`pkg/rule`, `adarve.report/v1`).
- ⚠️ Algunas consultas de Windows se hacen mediante PowerShell (lista blanca) en lugar de WMI nativo; se migrarán a llamadas nativas cuando compense.
