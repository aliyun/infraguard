---
title: Depuração de Políticas
---

# Depuração de Políticas Rego

Existem duas maneiras de depurar suas políticas Rego: usando declarações print ou usando o depurador VSCode.

## Método 1: Usar Declarações Print

### Uso Básico

Adicione declarações `print()` em qualquer lugar da sua política Rego:

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

### Formato de Saída

As declarações print enviam saída para stderr com localização do arquivo:

```
/path/to/policy.rego:42: Starting policy evaluation
/path/to/policy.rego:45: Checking resource: MyBucket
/path/to/policy.rego:46: Resource type: ALIYUN::OSS::Bucket
/path/to/policy.rego:49: Found violation for resource: MyBucket
```

### Exemplos de Uso Comum

**Inspecionar Dados de Entrada:**
```rego
print("Input keys:", object.keys(input))
print("Template version:", input.ROSTemplateFormatVersion)
print("Number of resources:", count(input.Resources))
```

**Depurar Iteração de Recursos:**
```rego
some name, resource in helpers.resources_by_types(rule_meta.resource_types)
print("Resource:", name)
print("Properties:", object.keys(resource.Properties))
```

**Verificar Condições:**
```rego
condition1 := some_check(resource)
print("Condition 1 result:", condition1)
```

**Inspecionar Variáveis:**
```rego
property := helpers.get_property(resource, "SomeProperty", null)
print("Property value:", property)
print("Property type:", type_name(property))
```

## Método 2: Usar Depurador VSCode

O VSCode fornece uma experiência de depuração mais poderosa com pontos de interrupção, inspeção de variáveis e execução passo a passo.

### Pré-requisitos

1. **Instalar OPA**

   Baixe e instale OPA do site oficial:
   
   https://www.openpolicyagent.org/docs#1-download-opa

2. **Instalar Regal**

   Instale Regal para desenvolvimento Rego aprimorado:
   
   https://www.openpolicyagent.org/projects/regal#download-regal

3. **Instalar Extensão OPA VSCode**

   Instale a extensão OPA oficial do marketplace VSCode:
   
   https://marketplace.visualstudio.com/items?itemName=tsandall.opa

### Passos de Configuração

1. **Preparar Entrada de Teste**

   Crie um arquivo chamado `input.json` no seu diretório de políticas com seus dados de teste:

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

2. **Definir Pontos de Interrupção**

   Abra seu arquivo de política `.rego` no VSCode e clique na margem esquerda para definir pontos de interrupção onde deseja pausar a execução.

3. **Iniciar Depuração**

   - Pressione `F5` ou vá para Executar → Iniciar Depuração
   - O depurador pausará nos seus pontos de interrupção
   - Você pode inspecionar variáveis, executar passo a passo e avaliar expressões

## Escolher um Método

- **Declarações Print**: Rápidas e simples, funcionam em qualquer ambiente, úteis para depuração em produção
- **Depurador VSCode**: Mais poderoso, depuração interativa com inspeção completa de variáveis, melhor para desenvolvimento

Você pode usar ambos os métodos juntos: use declarações print para verificações rápidas e o depurador para investigação profunda.
