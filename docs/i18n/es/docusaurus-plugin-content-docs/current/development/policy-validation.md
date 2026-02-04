---
title: Validación de Políticas
---

# Validación de Políticas

Valide sus políticas personalizadas antes de usarlas.

## Comando de Validación

```bash
infraguard policy validate <path>
```

## Qué se Valida

- Sintaxis de Rego
- Metadatos requeridos (`rule_meta` o `pack_meta`)
- Estructura adecuada de la regla deny
- Formato de cadena i18n

## Ejemplos

```bash
# Validar un solo archivo
infraguard policy validate rule.rego

# Validar un directorio
infraguard policy validate ./policies/

# Con opción de idioma
infraguard policy validate rule.rego --lang es
```

Para más información, consulte [Gestión de Políticas](../user-guide/managing-policies).
