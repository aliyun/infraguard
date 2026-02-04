---
title: Gestión de Políticas
---

# Gestión de Políticas

Aprenda cómo descubrir, gestionar y actualizar políticas en InfraGuard.

## Listar Políticas

### Listar Todas las Políticas

Ver todas las reglas y paquetes disponibles:

```bash
infraguard policy list
```

Esto muestra:
- Todas las reglas integradas
- Todos los paquetes de cumplimiento
- Políticas personalizadas (si las hay)

### Filtrar por Proveedor

Actualmente, InfraGuard soporta políticas de Aliyun. Las versiones futuras soportarán proveedores adicionales.

## Detalles de Políticas

### Obtener Información de Regla

Ver información detallada sobre una regla específica:

```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
```

La salida incluye:
- ID y nombre de la regla
- Nivel de severidad
- Descripción
- Razón del fallo
- Recomendación
- Tipos de recursos afectados

### Obtener Información de Paquete

Ver detalles del paquete de cumplimiento:

```bash
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

La salida incluye:
- ID y nombre del paquete
- Descripción
- Lista de reglas incluidas

## Actualizar Políticas

InfraGuard incluye políticas integradas, pero también puede descargar la última biblioteca de políticas:

```bash
infraguard policy update
```

Esto descarga políticas a `~/.infraguard/policies/`, que tiene prioridad sobre las políticas integradas.

## Limpiar Políticas

Para eliminar políticas descargadas de su directorio de usuario:

```bash
infraguard policy clean
```

Este comando:
- Elimina todas las políticas de `~/.infraguard/policies/`
- Solicita confirmación por defecto
- No afecta las políticas integradas (permanecen disponibles)
- No afecta las políticas del espacio de trabajo en `.infraguard/policies/`

### Limpieza Forzada (Sin Confirmación)

Para scripts o entornos no interactivos:

```bash
infraguard policy clean --force
# o
infraguard policy clean -f
```

### Prioridad de Carga de Políticas

InfraGuard carga políticas de tres fuentes con la siguiente prioridad (de mayor a menor):

1. **Políticas locales del espacio de trabajo**: `.infraguard/policies/` (relativo al directorio de trabajo actual)
2. **Políticas locales del usuario**: `~/.infraguard/policies/`
3. **Políticas integradas**: Integradas en el binario (respaldo)

Las políticas con el mismo ID de fuentes de mayor prioridad sobrescriben las de menor prioridad. Esto permite:
- **Políticas específicas del proyecto**: Definir reglas personalizadas en `.infraguard/policies/` que están bajo control de versiones con su proyecto
- **Personalizaciones del usuario**: Sobrescribir políticas integradas globalmente a través de `~/.infraguard/policies/`
- **Respaldo sin problemas**: Las políticas integradas funcionan sin configuración

## Validar Políticas Personalizadas

Antes de usar políticas personalizadas, valídelas:

```bash
infraguard policy validate ./my-custom-rule.rego
```

Esto verifica:
- Sintaxis de Rego
- Metadatos requeridos (`rule_meta` o `pack_meta`)
- Estructura adecuada de la regla deny

### Opciones de Validación

```bash
# Validar un solo archivo
infraguard policy validate rule.rego

# Validar un directorio
infraguard policy validate ./policies/

# Especificar idioma de salida
infraguard policy validate rule.rego --lang es
```

## Formatear Políticas

Formatee sus archivos de políticas usando el formateador OPA:

```bash
# Mostrar salida formateada
infraguard policy format rule.rego

# Escribir cambios de vuelta al archivo
infraguard policy format rule.rego --write

# Mostrar diff de cambios
infraguard policy format rule.rego --diff
```

## Organización de Políticas

### Políticas Integradas

Ubicadas en el binario bajo:
- `policies/aliyun/rules/` - Reglas individuales
- `policies/aliyun/packs/` - Paquetes de cumplimiento
- `policies/aliyun/lib/` - Bibliotecas auxiliares

### Políticas Personalizadas

#### Políticas Locales del Espacio de Trabajo (Específicas del Proyecto)

Almacene políticas específicas del proyecto en su directorio del proyecto:
- `.infraguard/policies/<provider>/rules/` - Reglas específicas del proyecto
- `.infraguard/policies/<provider>/packs/` - Paquetes específicos del proyecto
- `.infraguard/policies/<provider>/lib/` - Bibliotecas auxiliares específicas del proyecto

Estas políticas se cargan automáticamente cuando se ejecutan comandos de InfraGuard desde dentro del directorio del proyecto y pueden estar bajo control de versiones junto con sus plantillas IaC.

#### Políticas Locales del Usuario (Globales)

Almacene políticas personalizadas globales en su directorio home:
- `~/.infraguard/policies/<provider>/rules/` - Reglas personalizadas globales
- `~/.infraguard/policies/<provider>/packs/` - Paquetes personalizados globales
- `~/.infraguard/policies/<provider>/lib/` - Bibliotecas auxiliares personalizadas globales

Estas políticas están disponibles para todos los proyectos y pueden sobrescribir políticas integradas.
