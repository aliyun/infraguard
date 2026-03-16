---
title: infraguard lsp
---

# infraguard lsp

Inicia o servidor do Protocolo de Servidor de Linguagem (LSP) ROS para integração com editores.

## Sinopse

```bash
infraguard lsp [flags]
```

## Descrição

O comando `lsp` inicia um servidor do Protocolo de Servidor de Linguagem (LSP) que se comunica via entrada/saída padrão (stdio). Ele fornece suporte inteligente de edição para modelos ROS em editores como o VS Code, incluindo:

- **Auto-completar** — Tipos de recursos, propriedades, funções intrínsecas, alvos Ref/GetAtt
- **Diagnósticos em tempo real** — Versão do formato, tipos de recursos, propriedades obrigatórias, incompatibilidades de tipo
- **Documentação ao passar o cursor** — Descrições, informações de tipo, restrições para recursos e propriedades

O servidor LSP suporta formatos de modelo tanto YAML quanto JSON.

## Flags

| Flag | Tipo | Descrição |
|------|------|-----------|
| `--stdio` | bool | Usar transporte stdio (padrão, aceito para compatibilidade com editores) |

## Exemplos

### Iniciar o Servidor LSP

```bash
infraguard lsp
```

### Iniciar com o Flag stdio Explícito

```bash
infraguard lsp --stdio
```

## Integração com o Editor

O servidor LSP normalmente é iniciado automaticamente por extensões do editor. Para o VS Code, instale a [extensão InfraGuard](https://marketplace.visualstudio.com/items?itemName=aliyun.infraguard), que gerencia o ciclo de vida do LSP.

Para mais detalhes, consulte [Integração com o Editor](../user-guide/editor-integration).

## Códigos de Saída

- `0`: Servidor encerrado normalmente
