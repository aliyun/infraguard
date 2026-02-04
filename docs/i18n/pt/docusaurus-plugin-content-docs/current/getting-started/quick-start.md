---
title: Início Rápido
---

# Início Rápido

Este guia ajudará você a começar com o InfraGuard em apenas alguns minutos.

## Passo 1: Criar um Modelo ROS de Exemplo

Crie um arquivo chamado `template.yaml` com o seguinte conteúdo:

```yaml
ROSTemplateFormatVersion: '2015-09-01'
Description: Sample ECS instance

Resources:
  MyECS:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      ImageId: 'centos_7'
      InstanceType: 'ecs.t5-lc1m1.small'
      AllocatePublicIP: true
      SecurityGroupId: 'sg-xxxxx'
      VpcId: 'vpc-xxxxx'
      VSwitchId: 'vsw-xxxxx'
```

## Passo 2: Executar Sua Primeira Varredura

Escaneie o modelo usando uma regra integrada:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-and-anyip
```

Você deve ver uma saída indicando que a instância ECS tem um IP público alocado, o que é uma preocupação de segurança.

## Passo 3: Usar um Pacote de Conformidade

Em vez de regras individuais, você pode escanear com um pacote de conformidade inteiro:

```bash
infraguard scan template.yaml -p pack:aliyun:security-group-best-practice
```

## Passo 4: Gerar um Relatório

O InfraGuard suporta múltiplos formatos de saída:

### Formato Tabela (Padrão)

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

### Formato JSON

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

### Relatório HTML

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Abra `report.html` no seu navegador para ver um relatório interativo.

## Passo 5: Listar Políticas Disponíveis

Para ver todas as regras e pacotes disponíveis:

```bash
# Listar todas as políticas
infraguard policy list

# Obter detalhes sobre uma regra específica
infraguard policy get rule:aliyun:ecs-instance-no-public-ip

# Obter detalhes sobre um pacote de conformidade
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

## Casos de Uso Comuns

### Escanear com Múltiplas Políticas

Você pode aplicar múltiplas políticas em uma única varredura:

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

### Definir Preferência de Idioma

O InfraGuard suporta 7 idiomas:

```bash
# Saída em português
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang pt

# Saída em inglês
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang en

# Outros idiomas suportados: zh (Chinês), es (Espanhol), fr (Francês), de (Alemão), ja (Japonês)
```

Você também pode definir o idioma permanentemente:

```bash
infraguard config set lang pt
```

Códigos de idioma suportados: `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. O padrão é detectado automaticamente com base na configuração regional do seu sistema.

## Próximos Passos

- **Aprender Mais**: Leia o [Guia do Usuário](../user-guide/scanning-templates) para informações detalhadas
- **Explorar Políticas**: Navegue pela [Referência de Políticas](../policies/aliyun/rules) para ver todas as regras e pacotes disponíveis
- **Escrever Políticas Personalizadas**: Confira o [Guia de Desenvolvimento](../development/writing-rules) para criar suas próprias regras

## Obter Ajuda

Se você encontrar problemas:

1. Verifique a página [FAQ](../faq)
2. Revise as mensagens de erro cuidadosamente - elas geralmente incluem dicas úteis
3. Reporte problemas no [GitHub](https://github.com/aliyun/infraguard/issues)
