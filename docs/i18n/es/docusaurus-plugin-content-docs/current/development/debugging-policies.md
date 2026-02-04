---
title: Depuración de Políticas
---

# Depuración de Políticas Rego

Hay dos formas de depurar sus políticas Rego: usando declaraciones print o usando el depurador de VSCode.

## Método 1: Usar Declaraciones Print

### Uso Básico

Agregue declaraciones `print()` en cualquier lugar de su política Rego:

```rego
package infraguard.rules.aliyun.my_rule

import rego.v1
import data.infraguard.helpers

deny contains result if {
    print("Starting policy evaluation")
    
    some name, resource in helpers.resources_by_types(rule_meta.resource_types)
    print("Checking resource:", name)
    print("Resource type:", resource.Type)
    
    not is_compliant(resource)
    print("Found violation for resource:", name)
    
    result := {...}
}
```

### Formato de Salida

Las declaraciones print envían salida a stderr con ubicación de archivo:

```
/path/to/policy.rego:42: Starting policy evaluation
/path/to/policy.rego:45: Checking resource: MyBucket
/path/to/policy.rego:46: Resource type: ALIYUN::OSS::Bucket
/path/to/policy.rego:49: Found violation for resource: MyBucket
```

### Ejemplos de Uso Común

**Inspeccionar Datos de Entrada:**
```rego
print("Input keys:", object.keys(input))
print("Template version:", input.ROSTemplateFormatVersion)
print("Number of resources:", count(input.Resources))
```

**Depurar Iteración de Recursos:**
```rego
some name, resource in helpers.resources_by_types(rule_meta.resource_types)
print("Resource:", name)
print("Properties:", object.keys(resource.Properties))
```

**Verificar Condiciones:**
```rego
condition1 := some_check(resource)
print("Condition 1 result:", condition1)
```

**Inspeccionar Variables:**
```rego
property := helpers.get_property(resource, "SomeProperty", null)
print("Property value:", property)
print("Property type:", type_name(property))
```

## Método 2: Usar Depurador de VSCode

VSCode proporciona una experiencia de depuración más potente con puntos de interrupción, inspección de variables y ejecución paso a paso.

### Prerrequisitos

1. **Instalar OPA**

   Descargue e instale OPA desde el sitio web oficial:
   
   https://www.openpolicyagent.org/docs#1-download-opa

2. **Instalar Regal**

   Instale Regal para desarrollo mejorado de Rego:
   
   https://www.openpolicyagent.org/projects/regal#download-regal

3. **Instalar Extensión OPA de VSCode**

   Instale la extensión oficial de OPA desde el marketplace de VSCode:
   
   https://marketplace.visualstudio.com/items?itemName=tsandall.opa

### Pasos de Configuración

1. **Preparar Entrada de Prueba**

   Cree un archivo llamado `input.json` en su directorio de políticas con sus datos de prueba:

   ```json
   {
     "ROSTemplateFormatVersion": "2015-09-01",
     "Resources": {
       "MyBucket": {
         "Type": "ALIYUN::OSS::Bucket",
         "Properties": {
           "BucketName": "test-bucket",
           "AccessControl": "private"
         }
       }
     }
   }
   ```

2. **Establecer Puntos de Interrupción**

   Abra su archivo de política `.rego` en VSCode y haga clic en el margen izquierdo para establecer puntos de interrupción donde desee pausar la ejecución.

3. **Iniciar Depuración**

   - Presione `F5` o vaya a Ejecutar → Iniciar Depuración
   - El depurador se pausará en sus puntos de interrupción
   - Puede inspeccionar variables, ejecutar paso a paso y evaluar expresiones

## Elegir un Método

- **Declaraciones Print**: Rápido y simple, funciona en cualquier entorno, útil para depuración en producción
- **Depurador de VSCode**: Más potente, depuración interactiva con inspección completa de variables, mejor para desarrollo

Puede usar ambos métodos juntos: use declaraciones print para verificaciones rápidas y el depurador para investigación profunda.
