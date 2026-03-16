---
title: Integración con Editores
---

# Integración con Editores

InfraGuard proporciona integración con editores a través de un servidor Language Server Protocol (LSP) integrado y una extensión de VS Code, permitiendo soporte de edición inteligente para plantillas ROS.

## Extensión de VS Code

### Instalación

Instala la extensión **InfraGuard** desde el [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=aliyun.infraguard), o busca "InfraGuard" en el panel de extensiones de VS Code.

La extensión requiere que el CLI `infraguard` esté instalado y disponible en tu PATH. Consulta [Instalación](../getting-started/installation) para más detalles.

### Características

#### Autocompletado

Completado contextual en toda la estructura de la plantilla:

- **Tipos de recursos** — Todos los identificadores de tipos de recursos ALIYUN::*
- **Propiedades** — Propiedades de recursos con información de tipo, propiedades requeridas priorizadas
- **Funciones intrínsecas** — `Fn::Join`, `Fn::Sub`, `Fn::Select`, y más
- **Objetivos Ref/GetAtt** — Referencias a parámetros, recursos y sus atributos
- **Definiciones de parámetros** — Type, Default, AllowedValues y otras propiedades de parámetros
- **Secciones de nivel superior** — ROSTemplateFormatVersion, Parameters, Resources, Outputs, etc.

Cuando escribes un tipo de recurso, se inserta automáticamente un bloque `Properties` con todas las claves requeridas.

#### Diagnósticos en Tiempo Real

Valida tu plantilla mientras escribes:

- `ROSTemplateFormatVersion` faltante o inválido
- Tipos de recursos desconocidos
- Propiedades requeridas faltantes
- Incompatibilidades de tipo en valores de propiedades
- Definiciones de parámetros inválidas
- Claves YAML duplicadas
- Claves desconocidas con sugerencias "¿Quiso decir?"

#### Documentación al Pasar el Cursor

Pasa el cursor sobre los elementos para ver documentación contextual:

- **Tipos de recursos** — Descripción y enlace a documentación oficial
- **Propiedades** — Tipo, restricciones, si es requerido u opcional, comportamiento de actualización
- **Funciones intrínsecas** — Sintaxis y ejemplos de uso

#### Resaltado de Sintaxis

Resaltado de sintaxis mejorado para elementos específicos de ROS:

- `!Ref`, `Fn::Join` y otras funciones intrínsecas
- Identificadores de tipos de recursos `ALIYUN::*::*`

### Tipos de Archivo Soportados

| Pattern | Detection |
|---------|-----------|
| `*.ros.yaml` / `*.ros.yml` | Reconocido automáticamente como plantillas ROS |
| `*.ros.json` | Reconocido automáticamente como plantillas ROS |
| `*.yaml` / `*.json` | Detectado mediante `ROSTemplateFormatVersion` en el contenido |

### Comandos

| Command | Description |
|---------|-------------|
| **InfraGuard: Update ROS Schema** | Obtener el esquema más reciente de tipos de recursos desde la API de ROS |

### Actualizar el Esquema ROS

La extensión incluye un esquema integrado para tipos de recursos ROS. Para actualizarlo con las definiciones más recientes:

1. Abre la Paleta de Comandos (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Ejecuta **InfraGuard: Update ROS Schema**

Esto requiere que las credenciales de Alibaba Cloud estén configuradas. Consulta [`infraguard schema update`](../cli/schema) para la configuración de credenciales.

## Servidor LSP

El servidor LSP puede integrarse con cualquier editor que soporte el Language Server Protocol.

### Iniciar el Servidor

```bash
infraguard lsp
```

El servidor se comunica mediante stdio (entrada/salida estándar).

### Configuración del Editor

Para editores distintos de VS Code, configura el cliente LSP para:

1. Iniciar el servidor con `infraguard lsp`
2. Usar stdio como transporte
3. Asociar con tipos de archivo YAML y JSON

Consulta [`infraguard lsp`](../cli/lsp) para más detalles.
