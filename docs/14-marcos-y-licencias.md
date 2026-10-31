# 14 · Marcos normativos y licencias

## Marcos soportados en `references`

| Campo | Marco | Estado en el paquete oficial |
|---|---|---|
| `nist` | NIST SP 800-53 rev. 5 (controles) | ✅ en todas las reglas |
| `mitre_techniques` | MITRE ATT&CK (técnicas y subtécnicas) | ✅ en la mayoría |
| `mitre_mitigations` | MITRE ATT&CK (mitigaciones M1xxx) | ✅ en la mayoría |
| `cis` | CIS Benchmarks (Windows 10/11, Server, Ubuntu, RHEL, Debian) | 🔜 fase 1 |
| `stig` | DISA STIG | 🔜 fase 1 |
| `ens` | Esquema Nacional de Seguridad (RD 311/2022) y guías CCN-STIC | 🔜 fase 1 |

Previstos para los informes por marco (fase 5): ISO/IEC 27001:2022 (Anexo A), PCI DSS 4.0, NIS2 (art. 21) y el NIST Cybersecurity Framework 2.0. Se derivarán de los mapeos anteriores.

### ¿Por qué no hay identificadores CIS/STIG todavía?

Los números de recomendación de CIS cambian entre versiones del benchmark (por ejemplo, el 18.x.y de Windows 11 v3 no coincide con el de v4) y los IDs de STIG cambian con cada revisión. Un ID equivocado en un informe de cumplimiento resta credibilidad. Por eso:

1. Cada mapeo se añadirá **indicando la versión del benchmark** (p. ej. `cis: ["win11-v4.0.0:18.6.4.4"]`).
2. Se verificará contra el documento oficial y se probará en el laboratorio.
3. Los títulos y la intención de las reglas ya se alinean con CIS L1/L2, y las diferencias se documentan en `rationale`/`impact`. Por ejemplo, Adarve incluye auditd en L1 por su valor defensivo, aunque CIS lo sitúa en L2.

## Licencias de las fuentes

| Fuente | Licencia / condiciones | Qué podemos hacer |
|---|---|---|
| **DISA STIG** | Dominio público (Gobierno de EE. UU.) | Reutilizar textos e IDs libremente |
| **Microsoft Security Baselines** (SCT) | Descarga gratuita de Microsoft | Usar valores y referencias; no redistribuir los paquetes tal cual |
| **CIS Benchmarks** | Los PDF se publican bajo **CC BY-NC-SA 4.0** (uso no comercial). El uso comercial y los contenidos automatizados (Build Kits, CIS-CAT Pro) requieren **membresía de CIS SecureSuite** | Citar los IDs de recomendación y reglas con redacción propia. **No** copiar textos ni redistribuir contenido de CIS en un producto comercial sin acuerdo |
| **NIST SP 800-53** | Dominio público | Reutilizar libremente |
| **MITRE ATT&CK** | Licencia de uso de MITRE (gratuita, requiere atribución) | Referenciar IDs y enlazar; incluir el aviso de atribución en informes |
| **ENS / CCN-STIC** | Publicaciones del CCN, de acceso público | Referenciar y alinear; consultar al CCN antes de redistribuir guías |

> **Decisión pendiente:** si Adarve será un producto comercial, conviene valorar la membresía de CIS SecureSuite (permite declarar "CIS Benchmark™ Certified" y usar los Build Kits) o limitar la referencia CIS a los IDs.

Aviso de atribución recomendado en los informes:

> *MITRE ATT&CK® es una marca registrada de The MITRE Corporation. CIS Benchmarks™ es una marca registrada del Center for Internet Security, Inc.*

## Licencia de Adarve

🔜 **Pendiente de decidir** antes de publicar el repositorio. Opciones habituales:

| Modelo | Licencia | Encaja si… |
|---|---|---|
| Open source permisivo | Apache-2.0 | Quieres adopción máxima y contribuciones de empresas |
| Open core | Apache-2.0 (agente y motor) + comercial (servidor y UI de flota) | Quieres comunidad y un producto de pago |
| Copyleft de red | AGPL-3.0 | Quieres impedir que terceros ofrezcan Adarve como servicio cerrado |
| Propietario | Comercial | Producto cerrado |
