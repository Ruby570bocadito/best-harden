# ADR-0009 · Releases firmadas con una clave ECDSA propia

**Estado:** aceptada · **Fecha:** 2026-10

## Contexto
Hasta la v0.4, el instalador y `adarve update` solo comprobaban la suma SHA-256 de `checksums.txt`, que llega por el mismo canal que el binario: quien controle la descarga (una cuenta de GitHub comprometida, un espejo interno, un proxy) puede cambiar las dos cosas. Adarve se ejecuta como administrador, así que la descarga necesita **autenticidad**, no solo integridad.

La comprobación tiene que funcionar en tres sitios sin instalar nada: el binario Go, `install.sh` (cualquier Linux con bash) e `install.ps1` (Windows PowerShell 5.1 con .NET Framework).

## Opciones
- **cosign *keyless* (Sigstore).** Sin clave que custodiar, pero verificar en el cliente exige la librería de Sigstore en Go (decenas de dependencias), el binario `cosign` en los instaladores o conexión a Rekor. No hay forma razonable de hacerlo en PowerShell 5.1.
- **Atestación de procedencia de GitHub.** Ya se publica, pero verificarla necesita la CLI `gh`.
- **minisign / Ed25519.** Simple, pero .NET Framework no tiene Ed25519 y `openssl` solo lo verifica sobre ficheros desde la 3.0.
- **ECDSA P-256 sobre SHA-256 con una clave propia.** La verifican la librería estándar de Go, `openssl dgst` en cualquier versión y `System.Security.Cryptography.ECDsa` en .NET Framework 4.7 o posterior.

## Decisión
- Cada release publica `checksums.txt.sig`: firma ECDSA P-256 (DER) de `checksums.txt`, hecha por GoReleaser con `openssl` y la clave del secreto `ADARVE_SIGNING_KEY`.
- La clave pública va dentro del binario (`internal/selfupdate/release-signing.pub`) y de los dos instaladores; un test comprueba que es la misma en los tres.
- Se verifica la firma **antes** de creer ninguna suma. Sin firma, no se instala salvo con `--insecure` / `-Insecure` (para las versiones anteriores). Una firma inválida se rechaza siempre.
- Se sigue publicando la atestación de procedencia de GitHub, para quien quiera comprobar además desde qué workflow y etiqueta se construyó.

## Consecuencias
- ✅ Un espejo o una descarga manipulados no pueden hacer instalar otro binario: necesitarían la clave privada.
- ✅ Sin dependencias nuevas en el binario ni en los instaladores.
- ⚠️ Hay una clave que custodiar: vive solo en el secreto de GitHub y en una copia fuera de línea. Si se filtra, se rota (ver [11 · Desarrollo](../11-desarrollo.md#la-clave-de-firma)); los binarios ya instalados aceptan la nueva cuando se haya publicado una versión que la incluya.
- ⚠️ Los espejos internos tienen que copiar también `checksums.txt.sig`.
