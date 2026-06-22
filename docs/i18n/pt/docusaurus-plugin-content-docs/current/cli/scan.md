---
title: infraguard scan
---

# infraguard scan

Escaneie modelos ROS e configurações Terraform para detectar violações de conformidade.

## Sinopse

```bash
infraguard scan <template> -p <policy> [flags]
```

## Argumentos

- `<template>`: Caminho para um arquivo de modelo ROS, arquivo Terraform `.tf`, ou diretório com modelos suportados (obrigatório, argumento posicional)

## Flags

| Flag | Tipo | Descrição |
|------|------|-----------|
| `-p, --policy <id>` | string | Política a aplicar (pode ser usada múltiplas vezes, obrigatório) |
| `--format <format>` | string | Formato de saída (`table`, `json`, `html`) |
| `-o, --output <file>` | string | Caminho do arquivo de saída |
| `--lang <lang>` | string | Idioma de saída (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`) |
| `-m, --mode <mode>` | string | Modo de varredura: `static` para análise local ou `preview` para ROS PreviewStack API (padrão: `static`) |
| `-i, --input <value>` | string | Valores de parâmetros no formato `key=value`, formato JSON ou caminho de arquivo (pode ser especificado múltiplas vezes) |
| `--waivers <path>` | string | Caminho para o arquivo de isenções (padrão: detecção automática de `.infraguard/waivers.yaml`) |
| `--no-waivers` | bool | Ignorar todas as isenções (comentários inline e arquivo de isenções) |
| `--show-waived` | bool | Mostrar violações isentas em vez de ocultá-las |
| `--fail-on-expired` | bool | Tratar isenções expiradas como violações reais (padrão: `true`) |

## Isenções

Violações podem ser suprimidas com um motivo por meio de comentários inline ou de um arquivo
central `.infraguard/waivers.yaml`. Isenções ativas são ocultadas (e contabilizadas no
resumo); isenções expiradas reaparecem e fazem a build falhar por padrão. Consulte o
[Guia de isenções](../user-guide/waivers) e [infraguard waiver](./waiver).

## Exemplos

```bash
# Escanear com uma regra
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Escanear um projeto Terraform
infraguard scan ./terraform -p pack:aliyun:quick-start-compliance-pack

# Escanear um arquivo Terraform e passar variáveis
infraguard scan main.tf -p rule:aliyun:ecs-instance-no-public-ip --input terraform.tfvars

# Escanear com um pacote
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack

# Escanear com padrão curinga (todas as regras)
infraguard scan template.yaml -p "rule:*"

# Escanear com padrão curinga (todas as regras ECS)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# Gerar relatório HTML
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html

# Escanear usando modo preview
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview

# Escanear com parâmetros de modelo
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --input InstanceType=ecs.c6.large --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd

# Modo preview com parâmetros de arquivo JSON
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview --input parameters.json
```

## Códigos de Saída

- `0`: Nenhuma violação encontrada
- `1`: Violações encontradas
- `2`: Violações de alta severidade encontradas

Para mais detalhes, consulte [Escaneando Modelos](../user-guide/scanning-templates).
