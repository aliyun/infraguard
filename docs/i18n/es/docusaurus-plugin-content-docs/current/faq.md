---
title: Preguntas Frecuentes
---

# Preguntas Frecuentes

## General

### ¿Qué es InfraGuard?

InfraGuard es una herramienta de línea de comandos que valida plantillas Infrastructure as Code (IaC) contra políticas de cumplimiento antes del despliegue. Ayuda a detectar problemas de seguridad y cumplimiento temprano en el ciclo de desarrollo.

### ¿Qué proveedores de nube son compatibles?

Actualmente, InfraGuard soporta plantillas Alibaba Cloud (Aliyun) ROS. El soporte para otros proveedores puede agregarse en versiones futuras.

### ¿InfraGuard es gratuito?

Sí, InfraGuard es de código abierto y se publica bajo la Licencia Apache 2.0.

## Uso

### ¿Cómo escaneo una plantilla?

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

Consulte la [Guía de Inicio Rápido](./getting-started/quick-start) para más ejemplos.

### ¿Puedo usar múltiples políticas en un escaneo?

¡Sí! Use múltiples flags `-p`:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip -p pack:aliyun:quick-start-compliance-pack
```

### ¿Qué formatos de salida están disponibles?

InfraGuard soporta tres formatos:
- **Tabla**: Salida de consola coloreada (predeterminado)
- **JSON**: Legible por máquina para CI/CD
- **HTML**: Informe interactivo

### ¿Cómo cambio el idioma?

Use el flag `--lang` o configúrelo permanentemente:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang es
# O configurar permanentemente
infraguard config set lang es
```

InfraGuard soporta 7 idiomas:
- `en` - English (Inglés)
- `zh` - Chinese (中文)
- `es` - Spanish (Español)
- `fr` - French (Francés)
- `de` - German (Alemán)
- `ja` - Japanese (日本語)
- `pt` - Portuguese (Portugués)

## Políticas

### ¿Dónde se almacenan las políticas?

Las políticas están integradas en el binario. También puede almacenar políticas personalizadas en `~/.infraguard/policies/`.

### ¿Cómo actualizo las políticas?

```bash
infraguard policy update
```

### ¿Puedo escribir políticas personalizadas?

¡Sí! Las políticas se escriben en Rego (lenguaje Open Policy Agent). Consulte la [Guía de Desarrollo](./development/writing-rules).

### ¿Cómo valido mi política personalizada?

```bash
infraguard policy validate my-rule.rego
```
