# 16 · Formatos estables y compatibilidad

Otros programas y otras personas dependen de lo que Adarve escribe y lee: un pipeline que lee el JSON del escaneo, un SIEM que recibe el aviso por webhook, un paquete de reglas propio en `rules.d`, un `exceptions.yaml` escrito a mano o un script que mira el código de salida. Esta página dice qué es estable, qué puede cambiar dentro de la versión 1 y qué obliga a una versión nueva. La decisión está en el [ADR-0010](adr/0010-formatos-estables.md).

## Qué es estable

| Formato | Esquema | Dónde | Forma de referencia |
|---|---|---|---|
| Informe de escaneo | `adarve.report/v1` | `adarve scan --format json`, `-o informe.json`, los informes guardados | [`report.txt`](../internal/compat/testdata/report.txt) |
| Superficie de ataque | `adarve.surface/v1` | `adarve surface --format json`, los análisis guardados | [`surface.txt`](../internal/compat/testdata/surface.txt) |
| Aviso por webhook (JSON) | `adarve.notify/v1` | `adarve schedule notify --format json` | [`notify.txt`](../internal/compat/testdata/notify.txt) |
| Excepciones | `adarve.exceptions/v1` | `exceptions.yaml` en la carpeta de configuración | [`exceptions.txt`](../internal/compat/testdata/exceptions.txt) |
| Cambios de hardening | `adarve.change/v1` | los manifiestos de `snapshots/`: un rollback debe poder deshacer los cambios de versiones anteriores | [`change.txt`](../internal/compat/testdata/change.txt) |
| Configuración | — | `config.yaml` | [`config.txt`](../internal/compat/testdata/config.txt) |
| Reglas y perfiles | — | el paquete oficial y los propios (`rules.d`), que comprueba `adarve rules lint`; para los editores, [`rule.schema.json`](../rules/schema/rule.schema.json) | [paquete de referencia v1](../rules/testdata/v1/rules.d) |
| Línea de órdenes | — | comandos, opciones y códigos de salida | esta página |

Cada «forma de referencia» lista, campo a campo, la ruta, el tipo y si es opcional. Sirve de referencia para quien consume el formato y la vigilan los tests (ver [Cómo se hace cumplir](#cómo-se-hace-cumplir)).

## Qué puede cambiar dentro de la versión 1

**Se puede** (cambios compatibles, en cualquier versión 1.x):

- Añadir campos **opcionales** a cualquier formato.
- Añadir **valores nuevos** a una enumeración: estados de un control (como `manual`, que se añadió así), tipos de hallazgo, probes, operadores, tipos de acción, etiquetas de `platforms` y `requires`.
- Añadir reglas, perfiles, comandos y opciones.
- Mejorar los textos (títulos, descripciones, mensajes): no son parte del formato.

**No se puede** (cambios incompatibles, solo con un esquema nuevo, `…/v2`):

- Quitar o renombrar un campo, o cambiar su tipo o su significado.
- Convertir en obligatorio un campo opcional.
- Cambiar el nombre de un esquema (`adarve.report/v1`…).
- Cambiar el significado de un código de salida o de una opción, o quitar un comando o una opción sin el periodo de retirada (abajo).
- Reutilizar el ID de una regla retirada o cambiar el ID de una existente: los IDs (`LNX-SSH-001`) son estables y aparecen en excepciones, informes y pipelines.

La garantía va en un sentido: lo que funciona con una versión 1.x sigue funcionando con las siguientes, no al revés. Adarve rechaza los campos que no conoce en las reglas, para que una errata no pase desapercibida, así que un paquete de reglas que use un campo, un probe o un tipo de acción nuevos necesita la versión de Adarve que los trae.

## Qué debe hacer quien consume un formato

- **Leer el JSON, no la salida para personas.** El texto de la terminal y el HTML cambian de una versión a otra; para automatizar, `--format json` o `-o informe.json`.
- **Ignorar los campos que no conozca.** Una versión 1.x puede añadirlos.
- **Tolerar valores de enumeración que no conozca.** Por ejemplo, tratar un estado desconocido de un control como «sin evaluar» y no como un error.
- **No depender del orden** de los campos ni de los elementos de una lista, salvo donde se documente.
- **Comprobar el esquema** (`schema`) antes de leer: si no es la versión que espera, no adivinar.

## Versiones nuevas y periodo de retirada

- Un cambio incompatible crea un esquema nuevo (`adarve.report/v2`). Adarve sigue **leyendo** la versión anterior durante toda la versión mayor siguiente, como hoy lee lo que guardó con su nombre anterior, Bastion (esquemas `bastion.*/v1`): informes, análisis de superficie, excepciones y manifiestos de cambios, así que un rollback puede deshacer lo que aplicó Bastion.
- Un comando o una opción que se va a retirar se marca como obsoleto, avisa al usarse durante al menos una versión menor y solo desaparece en la siguiente versión mayor.

## Códigos de salida

| Código | Significado | Dónde |
|---|---|---|
| 0 | Correcto | todos |
| 1 | Error (perfil inexistente, reglas inválidas, sin permisos…) | todos |
| 2 | No se cumple el umbral pedido | `scan --min-score`, `surface --fail-on` |
| 3 | Algo ha empeorado desde el análisis anterior | `surface --fail-on-new`, `schedule run` |
| 130 | Interrumpido (Ctrl+C) | todos |

## Cómo se hace cumplir

- **Forma de cada formato** ([`internal/compat`](../internal/compat)): el test compara la forma de los tipos de Go (nombres JSON o YAML, tipos, opcionales) con su referencia en `testdata`. Si falta o cambia una línea, el test falla y lo marca como **cambio incompatible**. Si aparece una línea nueva, también falla, para que el cambio sea una decisión: si el campo es opcional, se acepta con `go test ./internal/compat -update` y el diff de la referencia queda en la revisión.
- **Nombres de los esquemas:** un test comprueba que siguen siendo `…/v1`.
- **Formato de reglas:** el paquete de referencia [`rules/testdata/v1`](../rules/testdata/v1/rules.d) usa toda la sintaxis (perfil que hereda del oficial, `requires`, referencias, `all`/`any` anidados, `default`, `each`, `on_missing`, acciones y `safety`) y debe cargar y validar siempre. Otro test comprueba que `rule.schema.json` admite exactamente las plataformas, requisitos, probes, operadores y tipos de acción del código.
- **Lectura de versiones anteriores:** [`testdata/bastion`](../internal/compat/testdata/bastion) reproduce la carpeta de datos de Bastion (excepciones, un informe de escaneo, un análisis de superficie y un manifiesto de cambios) y un test comprueba que Adarve la sigue leyendo.
