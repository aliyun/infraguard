---
title: Suporte a Recursos ROS
---

# Suporte a Recursos ROS

O InfraGuard suporta uma ampla gama de recursos de modelos ROS (Resource Orchestration Service) para análise estática e validação do seu código de infraestrutura.

## Funções

O InfraGuard suporta as seguintes funções ROS:

### Funções de String
- [`Fn::Join`](https://www.alibabacloud.com/help/en/ros/user-guide/function-join) - Junta strings com um delimitador
- [`Fn::Sub`](https://www.alibabacloud.com/help/en/ros/user-guide/function-sub) - Substitui variáveis em uma string
- [`Fn::Split`](https://www.alibabacloud.com/help/en/ros/user-guide/function-split) - Divide uma string em uma lista
- [`Fn::Replace`](https://www.alibabacloud.com/help/en/ros/user-guide/function-replace) - Substitui strings no texto
- [`Fn::Str`](https://www.alibabacloud.com/help/en/ros/user-guide/function-str) - Converte valores para strings
- [`Fn::Indent`](https://www.alibabacloud.com/help/en/ros/user-guide/function-indent) - Indenta texto

### Funções de Codificação
- [`Fn::Base64Encode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64encode) - Codifica para Base64
- [`Fn::Base64Decode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64decode) - Decodifica de Base64

### Funções de Lista
- [`Fn::Select`](https://www.alibabacloud.com/help/en/ros/user-guide/function-select) - Seleciona um elemento de uma lista
- [`Fn::Index`](https://www.alibabacloud.com/help/en/ros/user-guide/function-index) - Encontra o índice de um elemento
- [`Fn::Length`](https://www.alibabacloud.com/help/en/ros/user-guide/function-length) - Retorna o comprimento de uma lista ou string
- [`Fn::ListMerge`](https://www.alibabacloud.com/help/en/ros/user-guide/function-listmerge) - Mescla múltiplas listas

### Funções de Mapa
- [`Fn::FindInMap`](https://www.alibabacloud.com/help/en/ros/user-guide/function-findinmap) - Recupera valores de um mapeamento
- [`Fn::SelectMapList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-selectmaplist) - Seleciona valores de uma lista de mapas
- [`Fn::MergeMapToList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-mergemaptolist) - Mescla mapas em uma lista

### Funções Matemáticas
- [`Fn::Add`](https://www.alibabacloud.com/help/en/ros/user-guide/function-add) - Adiciona números
- [`Fn::Avg`](https://www.alibabacloud.com/help/en/ros/user-guide/function-avg) - Calcula média
- [`Fn::Max`](https://www.alibabacloud.com/help/en/ros/user-guide/function-max) - Retorna valor máximo
- [`Fn::Min`](https://www.alibabacloud.com/help/en/ros/user-guide/function-min) - Retorna valor mínimo
- [`Fn::Calculate`](https://www.alibabacloud.com/help/en/ros/user-guide/function-calculate) - Avalia expressões matemáticas

### Funções Condicionais
- [`Fn::If`](https://www.alibabacloud.com/help/en/ros/user-guide/function-if) - Retorna valores com base em condições
- [`Fn::Equals`](https://www.alibabacloud.com/help/en/ros/user-guide/function-equals) - Compara dois valores
- [`Fn::And`](https://www.alibabacloud.com/help/en/ros/user-guide/function-and) - E lógico
- [`Fn::Or`](https://www.alibabacloud.com/help/en/ros/user-guide/function-or) - OU lógico
- [`Fn::Not`](https://www.alibabacloud.com/help/en/ros/user-guide/function-not) - NÃO lógico
- [`Fn::Contains`](https://www.alibabacloud.com/help/en/ros/user-guide/function-contains) - Verifica se um valor está em uma lista
- [`Fn::Any`](https://www.alibabacloud.com/help/en/ros/user-guide/function-any) - Verifica se alguma condição é verdadeira
- [`Fn::EachMemberIn`](https://www.alibabacloud.com/help/en/ros/user-guide/function-eachmemberin) - Verifica se todos os elementos estão em outra lista
- [`Fn::MatchPattern`](https://www.alibabacloud.com/help/en/ros/user-guide/function-matchpattern) - Corresponde a um padrão

### Funções Utilitárias
- [`Fn::GetJsonValue`](https://www.alibabacloud.com/help/en/ros/user-guide/function-getjsonvalue) - Extrai valores de JSON
- [`Ref`](https://www.alibabacloud.com/help/en/ros/user-guide/ref) - Referencia parâmetros e recursos

## Condições

O InfraGuard suporta completamente o recurso [Condições ROS](https://www.alibabacloud.com/help/ros/user-guide/conditions), incluindo:

- **Definição de Condição** - Definir condições na seção `Conditions`
- **Funções de Condição** - Usar `Fn::Equals`, `Fn::And`, `Fn::Or`, `Fn::Not`, `Fn::If` em condições
- **Referências de Condição** - Referenciar condições em recursos e saídas
- **Resolução de Dependências** - Resolve automaticamente dependências de condições

## Sintaxe YAML Curta

O InfraGuard suporta a sintaxe YAML curta (notação de tag) para funções ROS:

- `!Ref` - Forma curta de `Ref`
- `!GetAtt` - Forma curta de `Fn::GetAtt`
- Todas as outras funções `Fn::*` podem ser escritas como `!FunctionName`

O analisador YAML converte automaticamente essas formas curtas para sua representação de mapa padrão durante o carregamento do modelo.

## Recursos Não Suportados

O InfraGuard foca em análise estática e atualmente não suporta os seguintes recursos no modo estático:

### Funções de Tempo de Execução
- `Fn::GetAtt` - Requer criação real de recursos para recuperar atributos
- `Fn::GetAZs` - Requer consulta em tempo de execução ao provedor de nuvem
- `Fn::GetStackOutput` - Requer acesso a saídas de outras pilhas

### Seções de Modelo
- `Locals` - Definições de variáveis locais
- `Transform` - Transformações e macros de modelo
- `Rules` - Regras de validação de modelo
- `Mappings` - Mapeamentos de valores estáticos (não analisados para violações de políticas)

### Referências Especiais
- Parâmetros pseudo (ex.: `ALIYUN::StackId`, `ALIYUN::Region`, etc.) - Parâmetros fornecidos pelo sistema

Esses recursos serão preservados como estão na saída da análise sem avaliação ou validação ao usar o modo estático.

> **Dica**: Para modelos que usam recursos não suportados por análise estática (como `Fn::GetAtt`, `Fn::GetAZs`, etc.), recomendamos usar `--mode preview` para aproveitar a API ROS PreviewStack para análise mais precisa. O modo preview avalia modelos com contexto real do provedor de nuvem, permitindo suporte para funções de tempo de execução e outros recursos dinâmicos.

## Recursos Relacionados

- [Estrutura de Modelo ROS](https://www.alibabacloud.com/help/en/ros/user-guide/template-structure)
- [Funções ROS](https://www.alibabacloud.com/help/en/ros/user-guide/functions)
- [Condições ROS](https://www.alibabacloud.com/help/en/ros/user-guide/conditions)
