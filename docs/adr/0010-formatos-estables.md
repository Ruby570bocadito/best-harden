# ADR-0010 · Formatos estables y política de compatibilidad

**Estado:** aceptada · **Fecha:** 2026-11

## Contexto
Adarve escribe y lee formatos de los que dependen otros: el JSON del escaneo y de la superficie (pipelines de CI/CD, SIEM), el aviso por webhook, los paquetes de reglas propios, `exceptions.yaml`, `config.yaml` y los manifiestos de cambios (un rollback debe poder deshacer lo que hizo una versión anterior). Hasta ahora llevaban un nombre de esquema versionado (`adarve.report/v1`…), pero nada impedía cambiarlos sin querer: renombrar un campo de Go o su etiqueta JSON pasaba todos los tests. La v1.0 promete estabilidad, así que hace falta una regla escrita y algo que la haga cumplir.

## Decisión
- Dentro de una versión mayor solo hay cambios **aditivos**: campos opcionales nuevos y valores nuevos en las enumeraciones. Quitar, renombrar o cambiar el tipo o el significado de un campo exige un esquema nuevo (`…/v2`), que convive con la lectura del anterior durante toda la versión mayor siguiente. Detalle en [16 · Formatos estables y compatibilidad](../16-formatos-y-compatibilidad.md).
- Quien consume un formato debe ignorar campos desconocidos y tolerar valores de enumeración desconocidos. Así se puede añadir, por ejemplo, el estado `manual` sin romper a nadie.
- La «forma» de cada formato (ruta, tipo y si es opcional, sacados por reflexión de los tipos de Go) se guarda en `internal/compat/testdata` y un test la compara en cada cambio. Cualquier diferencia hace fallar el test: si es incompatible, se rechaza; si es compatible, se acepta regenerando la referencia, y el diff queda en la revisión.
- El formato de reglas se fija con un paquete de referencia (`rules/testdata/v1`) que debe cargar siempre y con un test que compara `rule.schema.json` con lo que acepta el código.
- Lo que guardó una versión anterior se sigue leyendo. Un test lo comprueba con una carpeta de datos de Bastion, el nombre anterior de Adarve (esquemas `bastion.*/v1`).

## Alternativas
- **Publicar un JSON Schema de cada formato y validar contra él.** Útil para quien consume, pero hay que mantenerlo a mano a la par que los tipos de Go, y validar un documento de ejemplo no detecta un campo renombrado que el ejemplo no use. La forma por reflexión sale de los propios tipos y no se desincroniza.
- **Comparar un documento de ejemplo completo (golden JSON).** Depende de los datos (los campos `omitempty` vacíos no aparecen) y cambia con cada regla nueva del catálogo.

## Consecuencias
- ✅ Un cambio de formato deja de ser accidental: o falla el test, o se acepta a sabiendas.
- ✅ Las referencias de `testdata` sirven de documentación de los campos para quien integra Adarve.
- ✅ La prueba con los datos de Bastion sacó a la luz un fallo: los informes de escaneo que guardó Bastion (`bastion-*.json`) no aparecían en la historia de Adarve ni servían de referencia para los cambios desde el escaneo anterior. Ahora sí, y el test lo vigila.
- ⚠️ Las etiquetas de enumeración (los valores posibles de `status`, `severity`…) no están en la forma: los fijan sus tipos (`engine.Status`, `rule.Severity`) y esta política.
