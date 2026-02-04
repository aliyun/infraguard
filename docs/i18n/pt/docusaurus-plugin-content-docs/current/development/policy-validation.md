---
title: Validação de Políticas
---

# Validação de Políticas

Valide suas políticas personalizadas antes de usá-las.

## Comando de Validação

```bash
infraguard policy validate <path>
```

## O que é Validado

- Sintaxe Rego
- Metadados necessários (`rule_meta` ou `pack_meta`)
- Estrutura adequada da regra deny
- Formato de string i18n

## Exemplos

```bash
# Validar um único arquivo
infraguard policy validate rule.rego

# Validar um diretório
infraguard policy validate ./policies/

# Com opção de idioma
infraguard policy validate rule.rego --lang pt
```

Para mais informações, consulte [Gerenciando Políticas](../user-guide/managing-policies).
