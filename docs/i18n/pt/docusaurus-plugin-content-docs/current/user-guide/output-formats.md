---
title: Formatos de Saída
---

# Formatos de Saída

O InfraGuard suporta três formatos de saída: Tabela, JSON e HTML.

## Formato Tabela

Formato padrão com saída de console codificada por cores. Melhor para uso interativo.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

## Formato JSON

Formato legível por máquina para automação e pipelines CI/CD.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

## Formato HTML

Relatório interativo com capacidades de filtragem e pesquisa.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Para exemplos detalhados, consulte [Escaneando Modelos](./scanning-templates).
