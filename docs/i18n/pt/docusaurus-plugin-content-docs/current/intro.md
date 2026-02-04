---
title: Bem-vindo ao InfraGuard
sidebar_label: Introdução
---

# InfraGuard

**Política Definida. Infraestrutura Protegida.**

**CLI de pré-verificação de conformidade Infrastructure as Code (IaC)** para modelos Alibaba Cloud ROS.

Avalie seus modelos ROS YAML/JSON em relação a políticas de segurança e conformidade **antes da implantação**.

## O que é InfraGuard?

InfraGuard é uma ferramenta de linha de comando que ajuda você a garantir que seu código de infraestrutura atenda aos padrões de segurança e conformidade antes de implantar em produção. Ele usa Open Policy Agent (OPA) e políticas Rego para avaliar seus modelos.

## Política como Código

InfraGuard adota a abordagem **Policy as Code** - tratando políticas de conformidade como artefatos de código de primeira classe que podem ser versionados, testados e automatizados.

- **Controle de Versão** - Armazene políticas no Git junto com seu código de infraestrutura. Rastreie alterações, revise o histórico e reverta quando necessário.
- **Testes Automatizados** - Escreva testes unitários para suas políticas usando modelos de exemplo. Certifique-se de que as políticas funcionem corretamente antes de aplicá-las à produção.
- **Revisão de Código** - Aplique o mesmo processo de revisão por pares às alterações de políticas que você faz para o código do aplicativo. Detecte problemas cedo através da colaboração.
- **Integração CI/CD** - Integre verificações de políticas em seu pipeline CI/CD. Valide automaticamente cada alteração de infraestrutura em relação aos requisitos de conformidade.
- **Reutilização** - Compose regras individuais em pacotes de conformidade. Compartilhe políticas entre equipes e projetos para manter a consistência.
- **Declarativo** - Defina *o que* conformidade significa usando a sintaxe declarativa do Rego, não *como* verificá-la. Foque no resultado, não na implementação.

## Recursos Principais

- **Validação Pré-implantação** - Detecte problemas de conformidade antes que cheguem à produção
- **Pacotes de Políticas** - Pacotes de conformidade pré-construídos (MLPS, ISO 27001, PCI-DSS, etc.)
- **Internacionalização** - Suporte completo para 7 idiomas (Inglês, Chinês, Espanhol, Francês, Alemão, Japonês, Português)
- **Múltiplos Formatos de Saída** - Tabelas, JSON e relatórios HTML
- **Extensível** - Escreva políticas personalizadas em Rego
- **Rápido** - Construído em Go para velocidade e eficiência

## Provedores Suportados

- **Aliyun (Alibaba Cloud)** - Centenas de regras e dezenas de pacotes de conformidade

## Exemplo Rápido

```bash
# Escanear um modelo com um pacote de conformidade
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Escanear com regras específicas
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Gerar relatório HTML
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## Começar

Pronto para melhorar a conformidade da sua infraestrutura? Confira nosso [Guia de Início Rápido](./getting-started/quick-start) para começar.

## Biblioteca de Políticas

Navegue por nossa [Referência de Políticas](./policies/aliyun/rules) abrangente para ver todas as regras e pacotes de conformidade disponíveis.
