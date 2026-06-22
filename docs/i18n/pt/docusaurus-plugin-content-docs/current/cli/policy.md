---
title: infraguard policy
---

# infraguard policy

Gerenciar políticas de conformidade.

## Subcomandos

### list

Listar todas as políticas disponíveis:
```bash
infraguard policy list
```

### get

Obter detalhes de uma política específica:
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

Atualizar a biblioteca de políticas:
```bash
infraguard policy update
```

### new

Gerar a estrutura de uma nova regra personalizada (esqueleto Rego + fixtures de teste):
```bash
# Gerar uma regra para ROS e Terraform
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance

# Gerar o esqueleto de um pacote de conformidade
infraguard policy new --pack my-team-baseline
```

Os arquivos gerados ficam sob `--dir` (padrão `./policies`) e podem ser usados diretamente com `infraguard scan -p ./policies <template>` e `infraguard policy test`. Consulte [Criando Regras Personalizadas](../development/scaffolding-rules).

| Flag | Descrição | Padrão |
| --- | --- | --- |
| `--iac` | IaC alvo: `ros`, `terraform` ou `both` | `both` |
| `--severity` | `high`, `medium` ou `low` | `medium` |
| `--resource-type` | Tipo de recurso ROS (repetível) | — |
| `--tf-resource-type` | Tipo de recurso Terraform (repetível) | — |
| `--dir` | Diretório raiz de saída | `./policies` |
| `--name-en` / `--name-zh` | Nome da regra | ID da regra |
| `--desc-en` / `--desc-zh` | Descrição da regra | `TODO` |
| `--no-test` | Não gerar fixtures de teste | `false` |
| `--force` | Sobrescrever arquivos existentes | `false` |
| `--pack` | Gerar o esqueleto de um pacote com o ID fornecido | — |

### test

Executar testes de comportamento para regras usando suas fixtures:
```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule my-rule --iac terraform
infraguard policy test --dir ./policies --format json
```

Para cada regra, as fixtures sob `<dir>/testdata/aliyun/rules/<rule>/` são avaliadas: fixtures `compliant` não devem produzir **nenhuma** violação da regra, e fixtures `violation` devem produzir **pelo menos uma**. O código de saída é `0` quando todos os casos passam, `1` em caso de falha, e `2` quando nenhuma fixture é encontrada (a menos que `--allow-empty`). Consulte [Testando Regras](../development/scaffolding-rules).

| Flag | Descrição | Padrão |
| --- | --- | --- |
| `--dir` | Diretório raiz contendo `rules/` e `testdata/` | `./policies` |
| `--rule` | Testar apenas o ID de regra fornecido (repetível) | todas |
| `--iac` | IaC a testar: `ros`, `terraform` ou `both` | `both` |
| `--format` | Formato de saída: `table` ou `json` | `table` |
| `--allow-empty` | Sair com `0` mesmo quando nenhuma fixture é encontrada | `false` |

### validate

Validar políticas personalizadas:
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang pt
```

### format

Formatar arquivos de políticas:
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

### clean

Limpar o diretório de políticas do usuário:
```bash
infraguard policy clean              # Modo interativo com confirmação
infraguard policy clean --force      # Pular confirmação
infraguard policy clean -f           # Flag curto
```

Remove todas as políticas de `~/.infraguard/policies/`. Não afeta políticas incorporadas ou políticas do workspace.

Para mais detalhes, consulte [Gerenciando Políticas](../user-guide/managing-policies).
