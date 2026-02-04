<div align="center">
  <img src="../assets/logo.png" alt="InfraGuard Logo" width="200"/>
</div>

# InfraGuard

**Política Definida. Infraestrutura Protegida.**

**CLI de pré-verificação de conformidade Infrastructure as Code (IaC)** para modelos Alibaba Cloud ROS. Avalie seus modelos ROS YAML/JSON em relação a políticas de segurança e conformidade **antes da implantação**.

> 💡 InfraGuard adota **Policy as Code** - tratando políticas de conformidade como artefatos de código versionados, testáveis e reutilizáveis.

**Idioma**: [English](../README.md) | [中文](README.zh.md) | [Español](README.es.md) | [Français](README.fr.md) | [Deutsch](README.de.md) | [日本語](README.ja.md) | Português

## ✨ Recursos

- 🔍 **Validação Pré-implantação** - Detectar problemas de conformidade antes que cheguem à produção
- 🎯 **Modos de Varredura Dupla** - Análise estática ou validação de visualização baseada em nuvem
- 📦 **Regras Integradas** - Cobertura abrangente para serviços Aliyun
- 🏆 **Pacotes de Conformidade** - MLPS, ISO 27001, PCI-DSS, SOC 2 e mais
- 🌍 **Suporte Multilíngue** - Disponível em 7 idiomas (Português, Inglês, Chinês, Espanhol, Francês, Alemão, Japonês)
- 🎨 **Múltiplos Formatos de Saída** - Tabelas, JSON e relatórios HTML interativos
- 🔧 **Extensível** - Escreva políticas personalizadas em Rego (Open Policy Agent)
- ⚡ **Rápido** - Construído em Go para velocidade e eficiência

## 🚀 Início Rápido

### Instalação

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

Ou baixe binários pré-compilados de [GitHub Releases](https://github.com/aliyun/infraguard/releases).

### Uso Básico

```bash
# Escanear com um pacote de conformidade
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Escanear com uma regra específica
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Escanear com padrão curinga (todas as regras)
infraguard scan template.yaml -p "rule:*"

# Escanear com padrão curinga (todas as regras ECS)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# Gerar relatório HTML
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## 📚 Documentação

Para documentação detalhada, visite nosso [Site de Documentação](https://aliyun.github.io/infraguard/pt/)

- **[Primeiros Passos](https://aliyun.github.io/infraguard/pt/docs/getting-started/installation)** - Guia de instalação e início rápido
- **[Guia do Usuário](https://aliyun.github.io/infraguard/pt/docs/user-guide/scanning-templates)** - Aprenda como escanear modelos e gerenciar políticas
- **[Referência de Políticas](https://aliyun.github.io/infraguard/pt/docs/policies/aliyun/rules)** - Navegue por todas as regras e pacotes de conformidade disponíveis
- **[Guia de Desenvolvimento](https://aliyun.github.io/infraguard/pt/docs/development/writing-rules)** - Escreva regras e pacotes personalizados
- **[Referência CLI](https://aliyun.github.io/infraguard/pt/docs/cli/scan)** - Documentação da interface de linha de comando
- **[FAQ](https://aliyun.github.io/infraguard/pt/docs/faq)** - Perguntas frequentes
