---
title: Configuração
---

# Configuração

O InfraGuard armazena a configuração em `~/.infraguard/config.yaml`.

## Gerenciando Configuração

### Definir um Valor

```bash
infraguard config set lang pt
```

### Obter um Valor

```bash
infraguard config get lang
```

### Listar Todas as Configurações

```bash
infraguard config list
```

### Remover um Valor

```bash
infraguard config unset lang
```

## Configurações Disponíveis

### Idioma (`lang`)

Defina o idioma de saída padrão:

```bash
infraguard config set lang zh  # Chinese (中文)
infraguard config set lang en  # English (Inglês)
infraguard config set lang es  # Spanish (Espanhol)
infraguard config set lang fr  # French (Francês)
infraguard config set lang de  # German (Alemão)
infraguard config set lang ja  # Japanese (Japonês)
infraguard config set lang pt  # Portuguese (Português)
```

O InfraGuard suporta 7 idiomas: `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. O padrão é detectado automaticamente com base na configuração regional do seu sistema.

## Arquivo de Configuração

O arquivo de configuração está localizado em `~/.infraguard/config.yaml`:

```yaml
lang: pt
```

Você pode editar este arquivo diretamente se preferir.
