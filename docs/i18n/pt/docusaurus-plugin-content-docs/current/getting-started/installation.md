---
title: Instalação
---

# Instalação

## Usando go install (Recomendado)

A forma mais simples de instalar o InfraGuard é usar `go install`:

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

Isso baixará, compilará e instalará o binário `infraguard` no diretório `$GOPATH/bin` (ou `$HOME/go/bin` se `GOPATH` não estiver definido).

Certifique-se de que o diretório bin do Go esteja no seu PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Verificar Instalação

```bash
infraguard version
```

Você deve ver as informações de versão exibidas.

## Baixar Binários Pré-compilados

Você pode baixar binários pré-compilados de [GitHub Releases](https://github.com/aliyun/infraguard/releases).

### Plataformas Disponíveis

| Plataforma | Arquitetura | Nome do Arquivo |
|------------|-------------|-----------------|
| Linux | amd64 | `infraguard-vX.X.X-linux-amd64` |
| Linux | arm64 | `infraguard-vX.X.X-linux-arm64` |
| macOS | amd64 (Intel) | `infraguard-vX.X.X-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `infraguard-vX.X.X-darwin-arm64` |
| Windows | amd64 | `infraguard-vX.X.X-windows-amd64.exe` |
| Windows | arm64 | `infraguard-vX.X.X-windows-arm64.exe` |

### Passos de Instalação

1. Baixe o binário apropriado para sua plataforma da [página de Releases](https://github.com/aliyun/infraguard/releases)

2. Torne o binário executável (Linux/macOS):

```bash
chmod +x infraguard-*
```

3. Mova para um diretório no seu PATH:

```bash
# Linux/macOS
sudo mv infraguard-* /usr/local/bin/infraguard

# Ou para instalação apenas do usuário
mv infraguard-* ~/bin/infraguard
```

4. Verifique a instalação:

```bash
infraguard version
```

## Compilar a Partir do Código Fonte (Opcional)

Se você precisar modificar o código ou preferir compilar a partir do código fonte:

### Pré-requisitos

- **Go 1.24.6 ou posterior**
- **Git**
- **Make**

### Passos

```bash
# Clonar o repositório
git clone https://github.com/aliyun/infraguard.git
cd infraguard

# Compilar o binário
make build

# Opcionalmente instalar no seu PATH
sudo cp infraguard /usr/local/bin/
```

## Próximos Passos

Agora que você tem o InfraGuard instalado, prossiga para o [Guia de Início Rápido](./quick-start) para aprender como usá-lo.
