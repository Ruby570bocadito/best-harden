# Despliegue

Ejemplos para desplegar Adarve en muchos equipos. Cómo usarlos y qué hacer cuando algo falla: [17 · Guía de operación](../docs/17-guia-de-operacion.md).

| Fichero | Para qué |
|---|---|
| [`windows/Deploy-Adarve.ps1`](windows/Deploy-Adarve.ps1) | Instala o actualiza Adarve a una versión fija desde una carpeta y programa la ronda diaria. Lo ejecutan la GPO, Intune y Ansible |
| [`intune/Detect-Adarve.ps1`](intune/Detect-Adarve.ps1) | Regla de detección de la aplicación Win32 de Intune |
| [`intune/Detect-Postura.ps1`](intune/Detect-Postura.ps1) | Remediations de Intune: la puntuación de cada equipo y si llega al umbral |
| [`intune/Remediate-Postura.ps1`](intune/Remediate-Postura.ps1) | Remediations de Intune, opcional: la ola 1 de `harden` en los equipos que no llegan |
| [`ansible/adarve.yml`](ansible/adarve.yml) | Playbook para Linux: instala, programa la ronda diaria y trae el informe de cada equipo |

El CI los ejecuta en máquinas reales contra un espejo firmado con una clave de prueba: [`scripts/e2e/deploy-windows.ps1`](../scripts/e2e/deploy-windows.ps1) y [`scripts/e2e/deploy-linux.sh`](../scripts/e2e/deploy-linux.sh).
