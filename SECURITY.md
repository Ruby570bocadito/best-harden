# Política de seguridad

## Versiones con soporte

Solo la última versión publicada recibe correcciones de seguridad. Actualiza con `adarve update` o volviendo a ejecutar el instalador.

## Reportar una vulnerabilidad

**No abras un issue público.** Usa el [aviso privado de seguridad de GitHub](https://github.com/Ruby570bocadito/adarve/security/advisories/new) e incluye:

- versión de Adarve (`adarve version`) y sistema operativo;
- descripción, impacto y pasos para reproducirlo;
- si aplica, una prueba de concepto mínima.

Compromisos: acuse de recibo en 72 h, evaluación inicial en 7 días y publicación coordinada de la corrección con reconocimiento al investigador (si lo desea).

## Alcance

Especialmente relevante:

- ejecución de código a través de reglas, configuración o informes;
- elusión de la verificación de actualizaciones;
- XSS u otras inyecciones en el informe HTML a partir de datos del sistema auditado;
- escalada de privilegios mediante los ficheros o directorios de Adarve;
- resultados falsos "superado" que oculten una configuración insegura.

Modelo de amenazas y controles: [docs/08-seguridad-de-la-plataforma.md](docs/08-seguridad-de-la-plataforma.md).
