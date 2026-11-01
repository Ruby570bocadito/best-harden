# 07 · UI y diseño

Adarve tiene hoy dos superficies visuales: la **consola** y el **informe HTML**. La **consola web de flota** llegará en la fase 3. Las tres comparten el mismo lenguaje visual.

![La consola: la muralla y la simulación de la ola 1](assets/demo.gif)

| | |
|---|---|
| ![Informe claro](assets/informe-claro.png) | ![Informe oscuro](assets/informe-oscuro.png) |

Las capturas salen de datos de demostración (un servidor ficticio, `web-01`) y se regeneran con `node scripts/demo/capturas.mjs` (ver [11 · Desarrollo](11-desarrollo.md#datos-de-demostración-y-capturas)).

## Identidad: el adarve

El adarve es el camino de ronda en lo alto de la muralla, por donde el centinela la recorre y comprueba que está entera. Esa es la metáfora de toda la interfaz:

| En el código | En la interfaz |
|---|---|
| `scan` | la ronda |
| puntuación | el estado de la muralla (68 %) |
| control fallido | brecha |
| categoría | tramo |
| `harden` | reparar |
| `surface` | las puertas |
| `schedule` | la ronda diaria |

La voz es la de un centinela tranquilo: habla en primera persona, dice qué repara él y qué decides tú, y nunca asusta sin dar una salida («Hay 14 brechas: 10 las reparo yo solo y 4 necesitan tu decisión»). La metáfora vive en los textos y en la consola; los comandos y el informe para auditores mantienen los términos técnicos («Fallidos», «Superados»).

## Principios

1. **Los datos son lo único que "grita".** Superficies neutras, bordes de un píxel y el color reservado para el estado.
2. **El color nunca va solo.** Cada estado o severidad lleva icono y texto (✕ Fallido, ✓ Superado, ! Error, – No aplica). Esto hace los informes legibles con daltonismo y al imprimir en blanco y negro.
3. **Una cifra principal por vista.** La puntuación de postura es la cifra principal; el resto son tiras KPI y gráficos pequeños.
4. **Claro y oscuro de verdad.** Cada tema tiene sus propios valores de color; el oscuro no es una inversión automática del claro. Se respeta `prefers-color-scheme` y hay un selector manual.
5. **Accesible.** Navegable con teclado (`<details>`, botones reales), foco visible, `aria-pressed` en los filtros y diseño adaptable hasta 390 px sin scroll horizontal.

## Tokens de diseño

Tres colores de marca: **noche** (el fondo), **piedra** (la muralla) y **luna** (enlaces y acción). El tema oscuro es el de la marca y el que abre la consola; el informe, que se comparte e imprime, parte del claro.

| Rol | Día (claro) | Noche (oscuro) |
|---|---|---|
| Página | `#f2eee5` | `#0e1218` |
| Superficie (tarjeta) | `#fbf9f4` | `#151a22` |
| Texto principal | `#1a1d23` | `#ece6da` |
| Texto secundario | `#3d4250` | `#c9cdd4` |
| Línea fina | `#ddd5c4` | `#252c37` |
| Piedra (la muralla) | `#c9b48a` | `#cdbb95` |
| Luna (enlaces y acción) | `#2f5fa8` | `#9cc2ff` |

### Paleta de estado (fija, nunca tematizada)

| Rol | Día | Noche | Uso en Adarve |
|---|---|---|---|
| good | `#2e9a5a` | `#6fd99a` | Superado, intacto, puntuación ≥ 80 |
| warning | `#c79a00` | `#f2c94c` | Severidad media, errores, puntuación 60-79 |
| serious | `#c2621f` | `#ffa463` | Severidad alta, brechas |
| critical | `#b3261e` | `#ff8a7d` | Severidad crítica, puntuación < 60 |
| neutral | `#6e7381` | `#b9bfca` | Severidad baja, no aplica |

Tipografía: Bahnschrift (en Windows; en otros sistemas, una condensada del sistema) para las cifras grandes y los títulos, y la del sistema para el texto. Monoespaciada para IDs, rutas y valores (`ui-monospace`, Cascadia Code, Consolas). Sin fuentes externas: la CSP de la consola y del informe no permite cargarlas. Las etiquetas largas de la muralla se parten por sílabas, con guion.

## Informe HTML (✅)

| Bloque | Forma | Por qué |
|---|---|---|
| Postura | Cifra principal (64 px) + calificación A-F + medidor | Es el dato que se busca primero |
| Fallidos / superados / sin evaluar o excepciones / no aplican | Tiras KPI | Cuatro números de cabecera; un gráfico añadiría ruido |
| Empieza por aquí | Lista priorizada (severidad y riesgo de rotura) | Convierte el informe en un plan |
| Fallidos por severidad | Barras horizontales con escala compartida y valor al final | Comparar magnitudes de una categoría ordinal |
| Puntuación por categoría | Medidores 0-100, peores primero | Una proporción frente a un límite |
| Técnicas ATT&CK expuestas | Fichas enlazadas a attack.mitre.org | Pasa del lenguaje de cumplimiento al de amenazas |
| Controles evaluados | Tabla filtrable (estado, severidad, categoría, búsqueda) con detalle desplegable | Es la vista de tabla: todo valor es accesible sin depender de gráficos ni tooltips |

Cada control desplegado muestra la descripción, por qué importa, el **árbol de evidencias** (subcomprobaciones con valor actual, esperado y origen), la remediación (GPO y comandos con botón Copiar), el riesgo de rotura, el impacto y las referencias.

Características técnicas:

- **Un único fichero** sin dependencias externas: funciona sin conexión, se adjunta a un correo y se imprime a PDF (estilos de impresión incluidos).
- **Seguro ante datos hostiles**: ver [08-seguridad-de-la-plataforma.md](08-seguridad-de-la-plataforma.md#informe-html).
- El tema elegido se recuerda en `localStorage` (si está disponible).

## Consola local: `adarve ui` (✅)

| La muralla | Las puertas |
|---|---|
| ![Consola de Adarve: la muralla](assets/consola.png) | ![Consola de Adarve: las puertas](assets/consola-puertas.png) |

Un panel en el navegador para trabajar con un equipo, no solo mirar una foto. Se sirve desde el propio binario en `127.0.0.1` con un token por sesión y no tiene dependencias externas ([ADR-0008](adr/0008-consola-local.md)). Solo mira y hace rondas: las reparaciones se aplican desde la terminal.

| Pestaña | Contenido |
|---|---|
| **Muralla** | El estado de la muralla con la variación desde la ronda anterior y una frase que resume qué repara Adarve y qué decides tú. Cada **tramo** es una categoría: su altura es la puntuación y cada grieta, una brecha; al pulsarlo se ven sus brechas. **Simular ola 1, 2 o 3** recalcula la puntuación como si se aplicara (misma fórmula que el motor) y los tramos crecen. Debajo: las rondas como torres (cada una abre esa ronda), «Reparar ahora» con el comando listo para copiar, prioridades y brechas por severidad |
| **Brechas** | El informe HTML de la ronda, incrustado y abierto directamente en la tabla de controles |
| **Plan de reparación** | La simulación de `harden` para la ola 1, 2 o 3: el cambio «actual → nuevo» de cada control y qué queda para otra ola, para el acceso remoto, para la GPO o es manual |
| **Puertas** | Los puertos que escuchan en la red, agrupados por programa: **abiertas a cualquiera**, **con rastrillo** (solo desde ciertas redes) o **cerradas** por el firewall, con su hallazgo y cómo cerrarlas; la tabla completa, los recursos compartidos y quién tiene las llaves (administradores) |
| **Rondas** | La ronda diaria (`schedule`) y sus ejecuciones, las rondas guardadas con su puntuación y variación, y las reparaciones aplicadas con el comando para deshacerlas |
| **Excepciones** | Vigencia de cada excepción: en naranja si caduca en menos de 30 días, en rojo si ha caducado |

Al abrirla hace una ronda si la última tiene más de una hora. El botón **Hacer la ronda** añade una torre a las rondas. Temas noche (por defecto) y día, y diseño adaptable hasta 375 px sin scroll horizontal.

## Consola de texto (✅)

- Colores ANSI solo cuando la salida es una terminal y no está activo `NO_COLOR`/`--no-color`.
- En Windows se activa el modo VT. En la consola clásica (conhost), los símbolos Unicode que su fuente no tiene se sustituyen (✓ → √, ✗ → ×).
- Barra de progreso en stderr para no ensuciar la salida JSON.

## Consola web de flota (🔜 fase 3)

**Stack:** React + TypeScript + Vite + Tailwind + shadcn/ui + TanStack Query/Table + ECharts + Framer Motion. El mismo sistema de tokens que el informe.

```
┌─ ADARVE ──────────────────────────────────────────── Ctrl+K   🔔   👤 ┐
│              │  Postura global          Por plataforma                 │
│ ▸ Dashboard  │    ╭──────╮              Windows 11   ████████░░  82    │
│   Activos    │    │  78  │  ▲ +6 / 30d  Server 2022  ██████░░░░  64    │
│   Políticas  │    ╰──────╯              Linux        ████████░░  79    │
│   Hardening  │ ─────────────────────────────────────────────────────── │
│   Defensa    │  Controles más fallidos       Cobertura MITRE ATT&CK     │
│   Informes   │  ● SMBv1 habilitado    42 eq   ▓▓▓▓░░▓▓▓░▓▓░░▓▓        │
│   Excepciones│  ● LLMNR activo        38 eq   ▓▓░░░▓▓▓▓▓░▓▓▓░░        │
│   Ajustes    │  ● Root login SSH      12 eq   ▓▓▓▓▓▓░░▓▓▓▓▓▓▓▓        │
└──────────────┴─────────────────────────────────────────────────────────┘
```

| Pantalla | Contenido |
|---|---|
| Dashboard | Postura global y tendencia, por plataforma, controles más fallidos, mapa ATT&CK (mitigación y detección) |
| Activos | Tabla con filtros, etiquetas y puntuación por equipo |
| Detalle de equipo | Lo mismo que el informe HTML, con historial y botón "Corregir" |
| Políticas (`studio`) | Editor de perfiles con herencia, parámetros, overrides, importación y exportación |
| Plan de hardening | Diff, avisos de impacto, datos de `observe`, olas, anillos y aprobación |
| Defensa | Superficie de ataque, telemetría, hallazgos de `hunt`, `lockdown` |
| Informes | Ejecutivo, técnico, por marco, diferencial |
| Excepciones | Solicitudes, aprobaciones y caducidades |
| Historial | Línea de tiempo de cambios con rollback de un clic |

Reglas de interacción: un único bloque de filtros por vista que afecta a todos los gráficos; tooltips que complementan pero nunca son la única forma de leer un dato; tabla equivalente para cada gráfico; paleta de comandos (Ctrl+K).
