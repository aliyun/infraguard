---
title: Soporte de Características ROS
---

# Soporte de Características ROS

InfraGuard soporta una amplia gama de características de plantillas ROS (Resource Orchestration Service) para análisis estático y validación de su código de infraestructura.

## Funciones

InfraGuard soporta las siguientes funciones ROS:

### Funciones de Cadena
- [`Fn::Join`](https://www.alibabacloud.com/help/en/ros/user-guide/function-join) - Une cadenas con un delimitador
- [`Fn::Sub`](https://www.alibabacloud.com/help/en/ros/user-guide/function-sub) - Sustituye variables en una cadena
- [`Fn::Split`](https://www.alibabacloud.com/help/en/ros/user-guide/function-split) - Divide una cadena en una lista
- [`Fn::Replace`](https://www.alibabacloud.com/help/en/ros/user-guide/function-replace) - Reemplaza cadenas en texto
- [`Fn::Str`](https://www.alibabacloud.com/help/en/ros/user-guide/function-str) - Convierte valores a cadenas
- [`Fn::Indent`](https://www.alibabacloud.com/help/en/ros/user-guide/function-indent) - Indenta texto

### Funciones de Codificación
- [`Fn::Base64Encode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64encode) - Codifica a Base64
- [`Fn::Base64Decode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64decode) - Decodifica desde Base64

### Funciones de Lista
- [`Fn::Select`](https://www.alibabacloud.com/help/en/ros/user-guide/function-select) - Selecciona un elemento de una lista
- [`Fn::Index`](https://www.alibabacloud.com/help/en/ros/user-guide/function-index) - Encuentra el índice de un elemento
- [`Fn::Length`](https://www.alibabacloud.com/help/en/ros/user-guide/function-length) - Devuelve la longitud de una lista o cadena
- [`Fn::ListMerge`](https://www.alibabacloud.com/help/en/ros/user-guide/function-listmerge) - Fusiona múltiples listas

### Funciones de Mapa
- [`Fn::FindInMap`](https://www.alibabacloud.com/help/en/ros/user-guide/function-findinmap) - Recupera valores de un mapeo
- [`Fn::SelectMapList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-selectmaplist) - Selecciona valores de una lista de mapas
- [`Fn::MergeMapToList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-mergemaptolist) - Fusiona mapas en una lista

### Funciones Matemáticas
- [`Fn::Add`](https://www.alibabacloud.com/help/en/ros/user-guide/function-add) - Suma números
- [`Fn::Avg`](https://www.alibabacloud.com/help/en/ros/user-guide/function-avg) - Calcula promedio
- [`Fn::Max`](https://www.alibabacloud.com/help/en/ros/user-guide/function-max) - Devuelve valor máximo
- [`Fn::Min`](https://www.alibabacloud.com/help/en/ros/user-guide/function-min) - Devuelve valor mínimo
- [`Fn::Calculate`](https://www.alibabacloud.com/help/en/ros/user-guide/function-calculate) - Evalúa expresiones matemáticas

### Funciones Condicionales
- [`Fn::If`](https://www.alibabacloud.com/help/en/ros/user-guide/function-if) - Devuelve valores basados en condiciones
- [`Fn::Equals`](https://www.alibabacloud.com/help/en/ros/user-guide/function-equals) - Compara dos valores
- [`Fn::And`](https://www.alibabacloud.com/help/en/ros/user-guide/function-and) - AND lógico
- [`Fn::Or`](https://www.alibabacloud.com/help/en/ros/user-guide/function-or) - OR lógico
- [`Fn::Not`](https://www.alibabacloud.com/help/en/ros/user-guide/function-not) - NOT lógico
- [`Fn::Contains`](https://www.alibabacloud.com/help/en/ros/user-guide/function-contains) - Verifica si un valor está en una lista
- [`Fn::Any`](https://www.alibabacloud.com/help/en/ros/user-guide/function-any) - Verifica si alguna condición es verdadera
- [`Fn::EachMemberIn`](https://www.alibabacloud.com/help/en/ros/user-guide/function-eachmemberin) - Verifica si todos los elementos están en otra lista
- [`Fn::MatchPattern`](https://www.alibabacloud.com/help/en/ros/user-guide/function-matchpattern) - Coincide con un patrón

### Funciones de Utilidad
- [`Fn::GetJsonValue`](https://www.alibabacloud.com/help/en/ros/user-guide/function-getjsonvalue) - Extrae valores de JSON
- [`Ref`](https://www.alibabacloud.com/help/en/ros/user-guide/ref) - Referencia parámetros y recursos

## Condiciones

InfraGuard soporta completamente la característica [Condiciones ROS](https://www.alibabacloud.com/help/ros/user-guide/conditions), incluyendo:

- **Definición de Condición** - Definir condiciones en la sección `Conditions`
- **Funciones de Condición** - Usar `Fn::Equals`, `Fn::And`, `Fn::Or`, `Fn::Not`, `Fn::If` en condiciones
- **Referencias de Condición** - Referenciar condiciones en recursos y salidas
- **Resolución de Dependencias** - Resuelve automáticamente las dependencias de condiciones

## Sintaxis Corta YAML

InfraGuard soporta la sintaxis corta YAML (notación de etiqueta) para funciones ROS:

- `!Ref` - Forma corta de `Ref`
- `!GetAtt` - Forma corta de `Fn::GetAtt`
- Todas las demás funciones `Fn::*` pueden escribirse como `!FunctionName`

El analizador YAML convierte automáticamente estas formas cortas a su representación de mapa estándar durante la carga de la plantilla.

## Características No Soportadas

InfraGuard se enfoca en análisis estático y actualmente no soporta las siguientes características en modo estático:

### Funciones de Tiempo de Ejecución
- `Fn::GetAtt` - Requiere creación real de recursos para recuperar atributos
- `Fn::GetAZs` - Requiere consulta en tiempo de ejecución al proveedor de nube
- `Fn::GetStackOutput` - Requiere acceso a salidas de otras pilas

### Secciones de Plantilla
- `Locals` - Definiciones de variables locales
- `Transform` - Transformaciones y macros de plantilla
- `Rules` - Reglas de validación de plantilla
- `Mappings` - Mapeos de valores estáticos (no analizados para violaciones de políticas)

### Referencias Especiales
- Parámetros pseudo (p. ej., `ALIYUN::StackId`, `ALIYUN::Region`, etc.) - Parámetros proporcionados por el sistema

Estas características se preservarán tal cual en la salida del análisis sin evaluación o validación cuando se use el modo estático.

> **Consejo**: Para plantillas que usan características no soportadas por análisis estático (como `Fn::GetAtt`, `Fn::GetAZs`, etc.), recomendamos usar `--mode preview` para aprovechar la API ROS PreviewStack para un análisis más preciso. El modo preview evalúa plantillas con contexto real del proveedor de nube, permitiendo soporte para funciones de tiempo de ejecución y otras características dinámicas.

## Recursos Relacionados

- [Estructura de Plantilla ROS](https://www.alibabacloud.com/help/en/ros/user-guide/template-structure)
- [Funciones ROS](https://www.alibabacloud.com/help/en/ros/user-guide/functions)
- [Condiciones ROS](https://www.alibabacloud.com/help/en/ros/user-guide/conditions)
