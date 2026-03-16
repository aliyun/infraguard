---
title: infraguard lsp
---

# infraguard lsp

Iniciar el servidor del Protocolo de Servidor de Lenguaje (LSP) de ROS para integración con editores.

## Sinopsis

```bash
infraguard lsp [flags]
```

## Descripción

El comando `lsp` inicia un servidor del Protocolo de Servidor de Lenguaje (LSP) que se comunica mediante E/S estándar (stdio). Proporciona soporte de edición inteligente para plantillas ROS en editores como VS Code, incluyendo:

- **Autocompletado** — Tipos de recursos, propiedades, funciones intrínsecas, objetivos Ref/GetAtt
- **Diagnósticos en tiempo real** — Versión de formato, tipos de recursos, propiedades requeridas, incompatibilidades de tipo
- **Documentación al pasar el cursor** — Descripciones, información de tipo, restricciones para recursos y propiedades

El servidor LSP admite formatos de plantilla tanto YAML como JSON.

## Flags

| Flag | Tipo | Descripción |
|------|------|-------------|
| `--stdio` | bool | Usar transporte stdio (predeterminado, aceptado para compatibilidad con editores) |

## Ejemplos

### Iniciar el Servidor LSP

```bash
infraguard lsp
```

### Iniciar con el Flag stdio Explícito

```bash
infraguard lsp --stdio
```

## Integración del Editor

El servidor LSP normalmente se inicia automáticamente por extensiones del editor. Para VS Code, instale la [extensión InfraGuard](https://marketplace.visualstudio.com/items?itemName=aliyun.infraguard) que gestiona el ciclo de vida del LSP.

Para más detalles, consulte [Integración del Editor](../user-guide/editor-integration).

## Códigos de Salida

- `0`: El servidor finalizó normalmente
