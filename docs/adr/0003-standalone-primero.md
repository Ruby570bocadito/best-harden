# ADR-0003 · Modo standalone primero, flota después

**Estado:** aceptada · **Fecha:** 2026-10

## Contexto
Una plataforma de flota (servidor, agentes, UI, auth) es un proyecto grande. Sin un motor sólido y unas reglas correctas, la flota solo multiplicaría resultados poco fiables.

## Decisión
Construir primero el binario standalone (`scan`, informes, `harden`) y después reutilizar **el mismo binario** como agente (`adarve agent`) en la fase 3.

## Consecuencias
- ✅ Valor desde el primer día (consultores, auditores, CI/CD, redes aisladas).
- ✅ El motor se valida en el mundo real antes de escalar.
- ✅ Un solo binario que mantener y firmar.
- ⚠️ El formato de informe (`adarve.report/v1`) debe ser estable desde ya, porque será el contrato con el servidor.
