---
title: Escaneando Modelos
---

# Escaneando Modelos

O comando `infraguard scan` avalia seus modelos ROS em relação às políticas de conformidade.

## Uso Básico

```bash
infraguard scan <template> -p <policy>
```

### Argumentos Obrigatórios

- `<template>`: Caminho para o arquivo de modelo ROS (YAML ou JSON) - argumento posicional

### Flags Obrigatórios

- `-p, --policy <id>`: Política a aplicar (pode ser usada múltiplas vezes)

### Flags Opcionais

- `--format <format>`: Formato de saída (`table`, `json`, ou `html`)
- `-o, --output <file>`: Caminho do arquivo de saída (para formatos HTML e JSON)
- `--lang <lang>`: Idioma de saída (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`)
- `-m, --mode <mode>`: Modo de varredura: `static` para análise local ou `preview` para ROS PreviewStack API (padrão: `static`)
- `-i, --input <value>`: Valores de parâmetros no formato `key=value`, formato JSON ou caminho de arquivo (pode ser especificado múltiplas vezes)

## Tipos de Políticas

Você pode escanear com diferentes tipos de políticas:

### 1. Regras Individuais

Escanear com uma regra de conformidade específica:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip
```

### 2. Pacotes de Conformidade

Escanear com um pacote de conformidade pré-definido:

```bash
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### 3. Correspondência de Padrão Curinga

Use padrões curinga (`*`) para corresponder a múltiplas regras ou pacotes:

**Corresponder todas as regras:**
```bash
infraguard scan template.yaml -p "rule:*"
```

**Corresponder regras por prefixo:**
```bash
infraguard scan template.yaml -p "rule:aliyun:ecs-*"
```

### 4. Arquivos de Políticas Personalizadas

Escanear com seu próprio arquivo de política Rego:

```bash
infraguard scan template.yaml -p ./my-custom-rule.rego
```

### 5. Diretórios de Políticas

Escanear com todas as políticas em um diretório:

```bash
infraguard scan template.yaml -p ./my-policies/
```

## Modos de Varredura

O InfraGuard suporta dois modos de varredura:

### Modo Estático (Padrão)

Realiza análise estática local do modelo sem exigir acesso ao provedor de nuvem:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode static
```

Este modo analisa a estrutura do modelo e as configurações de recursos localmente. É rápido e não requer credenciais de nuvem, mas pode não suportar todos os recursos ROS (consulte [Suporte a Recursos ROS](./ros-features)).

### Modo Preview

Usa a API ROS PreviewStack para validar modelos com avaliação real do provedor de nuvem:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview
```

O modo preview fornece análise mais precisa para recursos que exigem avaliação em tempo de execução (como `Fn::GetAtt`, `Fn::GetAZs`, etc.). Este modo requer que as credenciais ROS estejam configuradas.

Para modelos que usam recursos não suportados por análise estática, recomendamos usar `--mode preview` para resultados mais precisos.

## Múltiplas Políticas

Aplicar múltiplas políticas em uma única varredura:

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

## Formatos de Saída

### Formato Tabela (Padrão)

Exibe resultados em uma tabela codificada por cores:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

Exemplo de saída:

```
┌──────────────────────┬────────────┬──────────────┬──────────────────────┬─────────────────────────┐
│ RULE ID              │ SEVERITY   │ RESOURCE     │ REASON               │ RECOMMENDATION          │
├──────────────────────┼────────────┼──────────────┼──────────────────────┼─────────────────────────┤
│ ecs-no-public-ip     │ high       │ MyECS        │ Public IP allocated  │ Use NAT Gateway instead │
└──────────────────────┴────────────┴──────────────┴──────────────────────┴─────────────────────────┘
```

### Formato JSON

Formato legível por máquina para integração CI/CD:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

Saída:

```json
{
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "violations": [
    {
      "rule_id": "ecs-no-public-ip",
      "severity": "high",
      "resource_id": "MyECS",
      "reason": "Public IP allocated",
      "recommendation": "Use NAT Gateway instead"
    }
  ]
}
```

### Relatório HTML

Relatório HTML interativo com filtragem e pesquisa:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Abra `report.html` no seu navegador para uma experiência interativa.

## Códigos de Saída

O InfraGuard usa diferentes códigos de saída para indicar resultados da varredura:

- `0`: Nenhuma violação encontrada
- `1`: Violações encontradas
- `2`: Violações de alta severidade encontradas

Isso é útil para pipelines CI/CD:

```bash
#!/bin/bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
if [ $? -eq 2 ]; then
  echo "Violações de alta severidade encontradas! Bloqueando implantação."
  exit 1
fi
```

## Exemplos

### Exemplo 1: Auditoria de Segurança

```bash
infraguard scan production.yaml \
  -p pack:aliyun:security-group-best-practice \
  -p pack:aliyun:resource-protection-best-practice \
  --format html \
  -o security-audit.html
```

### Exemplo 2: Verificação de Conformidade

```bash
infraguard scan template.yaml \
  -p pack:aliyun:mlps-level-3-pre-check-compliance-pack \
  -p pack:aliyun:iso-27001-compliance \
  --lang pt \
  --format json \
  -o compliance-report.json
```

### Exemplo 3: Integração CI/CD

```bash
# No seu pipeline CI/CD
infraguard scan "${TEMPLATE_FILE}" \
  -p pack:aliyun:quick-start-compliance-pack \
  --format json \
  --lang en
```

### Exemplo 4: Modo Preview com Parâmetros

Escanear usando modo preview com parâmetros de modelo:

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input InstanceType=ecs.c6.large \
  --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd
```

Você também pode fornecer parâmetros de um arquivo JSON:

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input parameters.json
```

## Dicas

1. **Comece com o Pacote de Início Rápido**: Use `pack:aliyun:quick-start-compliance-pack` para verificações essenciais
2. **Use Múltiplos Pacotes**: Combine múltiplos pacotes para cobertura abrangente
3. **Salve Relatórios**: Use formato HTML para relatórios de partes interessadas, JSON para automação
4. **Defina Idioma Uma Vez**: Use `infraguard config set lang pt` para evitar repetir o flag `--lang`

## Próximos Passos

- Aprenda sobre [Gerenciando Políticas](./managing-policies)
- Explore [Formatos de Saída](./output-formats) em detalhes
- Configure [Configuração](./configuration)
