---
title: Estructura de Directorio de Políticas
---

# Estructura de Directorio de Políticas

InfraGuard soporta múltiples fuentes de políticas con un sistema de prioridad claro para cargar políticas.

## Estructura de Directorio

### Estructura de Directorio de Políticas Estándar

Las políticas siguen una estructura de directorio primero por proveedor:

```
{policy-root}/
├── {provider}/
│   ├── rules/
│   │   ├── rule1.rego            # Reglas individuales
│   │   └── rule2.rego
│   └── packs/
│       ├── pack1.rego            # Paquetes de cumplimiento
│       └── pack2.rego
```

**Ejemplo:**

```
.infraguard/policies/
├── solution/
│   ├── rules/
│   │   ├── metadata-ros-composer-check.rego
│   │   ├── metadata-templatetags-check.rego
│   │   ├── parameter-sensitive-noecho-check.rego
│   │   └── security-group-open-ports-except-whitelist.rego
│   └── packs/
│       └── ros-best-practice.rego
```

## Prioridad de Carga de Políticas

InfraGuard carga políticas desde múltiples fuentes con la siguiente prioridad (de mayor a menor):

1. **Políticas locales del workspace**: `.infraguard/policies/` (directorio de trabajo actual)
2. **Políticas locales del usuario**: `~/.infraguard/policies/` (directorio home del usuario)
3. **Políticas integradas**: Integradas en el binario

Las políticas con el mismo ID de fuentes de mayor prioridad sobrescribirán las de fuentes de menor prioridad.

## Políticas Locales del Workspace

Las políticas locales del workspace se almacenan en el directorio `.infraguard/policies/` dentro de su directorio de trabajo actual. Esta es la ubicación de mayor prioridad e ideal para:

- Reglas y paquetes personalizados específicos del proyecto
- Sobrescribir políticas integradas para proyectos específicos
- Probar nuevas políticas antes de promocionarlas a usuario-local o integradas

### Usar Políticas del Workspace

1. Cree la estructura de directorios:

```bash
mkdir -p .infraguard/policies/myprovider/{rules,packs}
```

2. Agregue sus reglas o paquetes personalizados a los directorios apropiados

3. Liste las políticas disponibles:

```bash
infraguard policy list
```

Sus políticas del workspace aparecerán con el formato de ID: `rule:myprovider:rule-name` o `pack:myprovider:pack-name`

4. Úselas en escaneos:

```bash
infraguard scan template.yml -p "pack:myprovider:my-pack"
```

## Políticas Locales del Usuario

Las políticas locales del usuario se almacenan en `~/.infraguard/policies/` en su directorio home. Estas políticas están disponibles en todos los proyectos para su cuenta de usuario.

## Generación de ID

InfraGuard genera automáticamente IDs de políticas basados en la estructura de directorios:

- **Reglas**: `rule:{provider}:{rule-id}`
- **Paquetes**: `pack:{provider}:{pack-id}`

Donde `{provider}` se deriva del nombre del directorio padre (p. ej., `solution`, `aliyun`, `custom`).

## Próximos Pasos

- Aprenda a [Escribir Reglas](./writing-rules)
- Aprenda a [Escribir Paquetes](./writing-packs)
- Vea [Validación de Políticas](./policy-validation)
