# 01 · Visión y propuesta de valor

## El problema

El hardening de sistemas suele hacerse con scripts sueltos de PowerShell y Bash, hojas de cálculo con los controles de CIS y mucha confianza. Eso provoca:

| Problema habitual | Consecuencia |
|---|---|
| Scripts que se ejecutan "a ciegas" | Cambios que rompen aplicaciones en producción; miedo a endurecer |
| Sin vuelta atrás | Una mala directiva deja un servidor sin acceso RDP/SSH |
| Una herramienta por sistema operativo | Visión fragmentada; nadie sabe la postura real de la flota |
| Informes manuales | Auditorías caras, evidencias que no se pueden reproducir |
| La configuración se degrada | Lo que se endureció en enero ya no lo está en junio |
| Lenguaje de cumplimiento, no de amenazas | "Cumplimos el 80 % de CIS", pero ¿qué ataques seguimos sin cubrir? |

## La propuesta

**Adarve** es una plataforma para **auditar, endurecer, vigilar y documentar** la configuración de seguridad de Windows 10/11, Windows Server 2016-2025 y Linux con:

1. **Un solo motor y un solo formato de reglas** para todos los sistemas.
2. **Evidencias reproducibles**: cada resultado dice qué se leyó, de dónde y qué se esperaba.
3. **Seguridad en el cambio**: simulación, instantánea, verificación y rollback automático (fase 2).
4. **Lenguaje de amenazas**: cada control se mapea a MITRE ATT&CK. Además de "cumplimos X", Adarve dice "estas técnicas siguen abiertas".
5. **Una interfaz cuidada**: informe HTML hoy, consola web de flota mañana.
6. **Instalación y actualización en una línea**, con verificación criptográfica.

## Para quién

| Perfil | Uso principal |
|---|---|
| Administradores de sistemas | Endurecer servidores y puestos sin romper nada |
| Equipos de seguridad / SOC | Postura de la flota, desviaciones, cobertura ATT&CK |
| Consultores y auditores | Binario portable, informe profesional en minutos, sin instalar nada |
| MSSP | Multi-cliente, informes con marca blanca (fase 5) |
| DevOps / plataforma | Validar imágenes doradas en CI/CD con `--min-score` |
| Administración pública (España) | Evidencias para ENS / CCN-STIC |

## Diferenciadores

Herramientas de referencia estudiadas: Lynis, OpenSCAP, CIS-CAT, HardeningKitty, Microsoft Security Compliance Toolkit, Ansible Lockdown y Wazuh SCA. Ninguna reúne todo lo siguiente:

- **Multiplataforma real** con un único motor y formato de reglas.
- **Modo observación** (fase 3): activa la auditoría nativa de Windows y Linux antes de aplicar un control y demuestra con datos que aplicarlo no rompe nada.
- **Remediación transaccional** con rollback y *dead-man switch* para el acceso remoto.
- **Consciente de GPO e Intune**: no "arregla" en local lo que una GPO va a volver a pisar.
- **Exportación** a GPO, Intune, Ansible, DSC y scripts, para adoptarlo sin cambiar de herramientas.
- **Mapa ATT&CK** de mitigación y, más adelante, de detección.
- **Dos modos** (standalone y flota) sobre el mismo motor.

## Principios

1. **No romper nada.** Todo cambio es simulable, reversible y verificado.
2. **Evidencia o no ha pasado.** Cada resultado es reproducible y explicable.
3. **Sin ejecución arbitraria.** Adarve no es, ni puede convertirse en, una herramienta de control remoto.
4. **Honestidad.** Si un dato no se puede leer, el resultado es "error" y nunca un "superado" inventado. Si un control no aplica, se dice.
5. **Opinión con criterio.** Perfiles por defecto sensatos; todo es configurable.
6. **Defensivo por diseño.** Adarve observa, evalúa y endurece. No incluye capacidades ofensivas.
