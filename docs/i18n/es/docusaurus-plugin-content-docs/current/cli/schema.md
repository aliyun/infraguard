---
title: infraguard schema
---

# infraguard schema

Gestiona el esquema de tipos de recursos ROS utilizado por el servidor LSP.

## Subcomandos

### update

Obtener el último esquema de tipos de recursos ROS desde la API ROS de Alibaba Cloud y guardarlo localmente:

```bash
infraguard schema update
```

## Descripción

El comando `schema` gestiona el esquema de tipos de recursos ROS que el servidor LSP utiliza para autocompletado, validación y documentación al pasar el cursor. El esquema contiene definiciones de todos los tipos de recursos ROS, sus propiedades, tipos y restricciones.

### Requisitos Previos

El subcomando `schema update` requiere credenciales de Alibaba Cloud. Configúrelas usando una de las siguientes opciones:

1. **Variables de entorno**:
   ```bash
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
   export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
   ```

2. **Configuración de Aliyun CLI**:
   ```bash
   aliyun configure
   ```

## Ejemplos

### Actualizar el Esquema

```bash
infraguard schema update
```

Salida:
```
Updating ROS resource type schema...
Schema updated successfully (350 resource types)
```

## Códigos de Salida

- `0`: Éxito
- `1`: Error (p. ej., credenciales faltantes, fallo de red)
