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
