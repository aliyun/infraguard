<div align="center">
  <img src="../assets/logo.png" alt="InfraGuard Logo" width="200"/>
</div>

# InfraGuard

**Política Definida. Infraestructura Asegurada.**

**CLI de pre-verificación de cumplimiento de Infrastructure as Code (IaC)** para plantillas de Alibaba Cloud ROS. Evalúe sus plantillas ROS YAML/JSON contra políticas de seguridad y cumplimiento **antes del despliegue**.

> 💡 InfraGuard adopta **Policy as Code** - tratando las políticas de cumplimiento como artefactos de código versionados, probables y reutilizables.

**Idioma**: [English](../README.md) | [中文](README.zh.md) | Español | [Français](README.fr.md) | [Deutsch](README.de.md) | [日本語](README.ja.md) | [Português](README.pt.md)

## ✨ Características

- 🔍 **Validación Pre-despliegue** - Detectar problemas de cumplimiento antes de que lleguen a producción
- 🎯 **Modos de Escaneo Dual** - Análisis estático o validación de vista previa basada en la nube
- 📦 **Reglas Integradas** - Cobertura integral para servicios de Aliyun
- 🏆 **Paquetes de Cumplimiento** - MLPS, ISO 27001, PCI-DSS, SOC 2 y más
- 🌍 **Soporte Multilingüe** - Disponible en 7 idiomas (Español, Inglés, Chino, Francés, Alemán, Japonés, Portugués)
- 🎨 **Múltiples Formatos de Salida** - Tablas, JSON e informes HTML interactivos
- 🔧 **Extensible** - Escriba políticas personalizadas en Rego (Open Policy Agent)
- ⚡ **Rápido** - Construido en Go para velocidad y eficiencia

## 🚀 Inicio Rápido

### Instalación

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

O descargue binarios precompilados de [GitHub Releases](https://github.com/aliyun/infraguard/releases).

### Uso Básico

```bash
# Escanear con un paquete de cumplimiento
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Escanear con una regla específica
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Escanear con patrón comodín (todas las reglas)
infraguard scan template.yaml -p "rule:*"

# Escanear con patrón comodín (todas las reglas ECS)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# Generar informe HTML
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## 📚 Documentación

Para documentación detallada, visite nuestro [Sitio de Documentación](https://aliyun.github.io/infraguard)

- **[Primeros Pasos](https://aliyun.github.io/infraguard/docs/getting-started/installation)** - Guía de instalación e inicio rápido
- **[Guía de Usuario](https://aliyun.github.io/infraguard/docs/user-guide/scanning-templates)** - Aprenda cómo escanear plantillas y gestionar políticas
- **[Referencia de Políticas](https://aliyun.github.io/infraguard/docs/policies/aliyun/rules)** - Explore todas las reglas y paquetes de cumplimiento disponibles
- **[Guía de Desarrollo](https://aliyun.github.io/infraguard/docs/development/writing-rules)** - Escriba reglas y paquetes personalizados
- **[Referencia CLI](https://aliyun.github.io/infraguard/docs/cli/scan)** - Documentación de la interfaz de línea de comandos
- **[FAQ](https://aliyun.github.io/infraguard/docs/faq)** - Preguntas frecuentes
