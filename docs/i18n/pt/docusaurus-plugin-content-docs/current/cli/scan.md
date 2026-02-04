---
title: infraguard scan
---

# infraguard scan

Escaneie modelos ROS para detectar violações de conformidade.

## Sinopse

```bash
infraguard scan <template> -p <policy> [flags]
```

## Argumentos

- `<template>`: Caminho para o arquivo de modelo ROS (obrigatório, argumento posicional)

## Flags

| Flag | Tipo | Descrição |
|------|------|-----------|
| `-p, --policy <id>` | string | Política a aplicar (pode ser usada múltiplas vezes, obrigatório) |
| `--format <format>` | string | Formato de saída (`table`, `json`, `html`) |
| `-o, --output <file>` | string | Caminho do arquivo de saída |
| `--lang <lang>` | string | Idioma de saída (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`) |
| `-m, --mode <mode>` | string | Modo de varredura: `static` para análise local ou `preview` para ROS PreviewStack API (padrão: `static`) |
| `-i, --input <value>` | string | Valores de parâmetros no formato `key=value`, formato JSON ou caminho de arquivo (pode ser especificado múltiplas vezes) |

## Exemplos

```bash
# Escanear com uma regra
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

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
