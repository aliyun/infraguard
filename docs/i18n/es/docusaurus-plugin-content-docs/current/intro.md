---
title: Bienvenido a InfraGuard
sidebar_label: Introducción
---

# InfraGuard

**Política Definida. Infraestructura Protegida.**

**CLI de pre-verificación de cumplimiento Infrastructure as Code (IaC)** para plantillas Alibaba Cloud ROS.

Evalúe sus plantillas ROS YAML/JSON contra políticas de seguridad y cumplimiento **antes del despliegue**.

## ¿Qué es InfraGuard?

InfraGuard es una herramienta de línea de comandos que le ayuda a asegurar que su código de infraestructura cumpla con los estándares de seguridad y cumplimiento antes de desplegar en producción. Utiliza Open Policy Agent (OPA) y políticas Rego para evaluar sus plantillas.

## Política como Código

InfraGuard adopta el enfoque **Policy as Code** - tratando las políticas de cumplimiento como artefactos de código de primera clase que pueden ser versionados, probados y automatizados.

- **Control de Versiones** - Almacene políticas en Git junto con su código de infraestructura. Rastree cambios, revise historial y revierta cuando sea necesario.
- **Pruebas Automatizadas** - Escriba pruebas unitarias para sus políticas usando plantillas de ejemplo. Asegúrese de que las políticas funcionen correctamente antes de aplicarlas a producción.
- **Revisión de Código** - Aplique el mismo proceso de revisión por pares a los cambios de políticas que hace para el código de aplicación. Detecte problemas temprano a través de la colaboración.
- **Integración CI/CD** - Integre verificaciones de políticas en su pipeline CI/CD. Valide automáticamente cada cambio de infraestructura contra los requisitos de cumplimiento.
- **Reutilización** - Componga reglas individuales en paquetes de cumplimiento. Comparta políticas entre equipos y proyectos para mantener la consistencia.
- **Declarativo** - Defina *qué* significa cumplimiento usando la sintaxis declarativa de Rego, no *cómo* verificarlo. Enfóquese en el resultado, no en la implementación.

## Características Clave

- **Validación Pre-despliegue** - Detecte problemas de cumplimiento antes de que lleguen a producción
- **Paquetes de Políticas** - Paquetes de cumplimiento preconstruidos (MLPS, ISO 27001, PCI-DSS, etc.)
- **Internacionalización** - Soporte completo para 7 idiomas (Inglés, Chino, Español, Francés, Alemán, Japonés, Portugués)
- **Múltiples Formatos de Salida** - Tablas, JSON e informes HTML
- **Extensible** - Escriba políticas personalizadas en Rego
- **Rápido** - Construido en Go para velocidad y eficiencia

## Proveedores Soportados

- **Aliyun (Alibaba Cloud)** - Cientos de reglas y docenas de paquetes de cumplimiento

## Ejemplo Rápido

```bash
# Escanear una plantilla con un paquete de cumplimiento
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Escanear con reglas específicas
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Generar informe HTML
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## Comenzar

¿Listo para mejorar el cumplimiento de su infraestructura? Consulte nuestra [Guía de Inicio Rápido](./getting-started/quick-start) para comenzar.

## Biblioteca de Políticas

Explore nuestra [Referencia de Políticas](./policies/aliyun/rules) completa para ver todas las reglas y paquetes de cumplimiento disponibles.
