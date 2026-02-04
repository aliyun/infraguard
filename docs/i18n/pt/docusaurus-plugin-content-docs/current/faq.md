---
title: Perguntas Frequentes
---

# Perguntas Frequentes

## Geral

### O que é InfraGuard?

InfraGuard é uma ferramenta de linha de comando que valida modelos Infrastructure as Code (IaC) contra políticas de conformidade antes da implantação. Ajuda a detectar problemas de segurança e conformidade no início do ciclo de desenvolvimento.

### Quais provedores de nuvem são suportados?

Atualmente, InfraGuard suporta modelos Alibaba Cloud (Aliyun) ROS. O suporte para outros provedores pode ser adicionado em versões futuras.

### InfraGuard é gratuito?

Sim, InfraGuard é open source e lançado sob a Licença Apache 2.0.

## Uso

### Como escaneio um modelo?

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

Veja o [Guia de Início Rápido](./getting-started/quick-start) para mais exemplos.

### Posso usar múltiplas políticas em uma varredura?

Sim! Use múltiplas flags `-p`:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip -p pack:aliyun:quick-start-compliance-pack
```

### Quais formatos de saída estão disponíveis?

InfraGuard suporta três formatos:
- **Tabela**: Saída de console colorida (padrão)
- **JSON**: Legível por máquina para CI/CD
- **HTML**: Relatório interativo

### Como mudo o idioma?

Use a flag `--lang` ou configure permanentemente:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang pt
# Ou configurar permanentemente
infraguard config set lang pt
```

InfraGuard suporta 7 idiomas:
- `en` - English (Inglês)
- `zh` - Chinese (中文)
- `es` - Spanish (Espanhol)
- `fr` - French (Francês)
- `de` - German (Alemão)
- `ja` - Japanese (Japonês)
- `pt` - Portuguese (Português)

## Políticas

### Onde as políticas são armazenadas?

As políticas estão incorporadas no binário. Você também pode armazenar políticas personalizadas em `~/.infraguard/policies/`.

### Como atualizo as políticas?

```bash
infraguard policy update
```

### Posso escrever políticas personalizadas?

Sim! As políticas são escritas em Rego (linguagem Open Policy Agent). Veja o [Guia de Desenvolvimento](./development/writing-rules).

### Como valido minha política personalizada?

```bash
infraguard policy validate my-rule.rego
```
