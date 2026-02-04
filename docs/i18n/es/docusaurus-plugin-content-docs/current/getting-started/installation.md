---
title: Instalación
---

# Instalación

## Usando go install (Recomendado)

La forma más simple de instalar InfraGuard es usando `go install`:

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

Esto descargará, compilará e instalará el binario `infraguard` en su directorio `$GOPATH/bin` (o `$HOME/go/bin` si `GOPATH` no está configurado).

Asegúrese de que su directorio bin de Go esté en su PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

### Verificar Instalación

```bash
infraguard version
```

Debería ver la información de versión mostrada.

## Descargar Binarios Precompilados

Puede descargar binarios precompilados desde [GitHub Releases](https://github.com/aliyun/infraguard/releases).

### Plataformas Disponibles

| Plataforma | Arquitectura | Nombre de Archivo |
|------------|--------------|-------------------|
| Linux | amd64 | `infraguard-vX.X.X-linux-amd64` |
| Linux | arm64 | `infraguard-vX.X.X-linux-arm64` |
| macOS | amd64 (Intel) | `infraguard-vX.X.X-darwin-amd64` |
| macOS | arm64 (Apple Silicon) | `infraguard-vX.X.X-darwin-arm64` |
| Windows | amd64 | `infraguard-vX.X.X-windows-amd64.exe` |
| Windows | arm64 | `infraguard-vX.X.X-windows-arm64.exe` |

### Pasos de Instalación

1. Descargue el binario apropiado para su plataforma desde la [página de Releases](https://github.com/aliyun/infraguard/releases)

2. Haga el binario ejecutable (Linux/macOS):

```bash
chmod +x infraguard-*
```

3. Muévalo a un directorio en su PATH:

```bash
# Linux/macOS
sudo mv infraguard-* /usr/local/bin/infraguard

# O para instalación solo de usuario
mv infraguard-* ~/bin/infraguard
```

4. Verifique la instalación:

```bash
infraguard version
```

## Compilar desde el Código Fuente (Opcional)

Si necesita modificar el código o prefiere compilar desde el código fuente:

### Prerrequisitos

- **Go 1.24.6 o posterior**
- **Git**
- **Make**

### Pasos

```bash
# Clonar el repositorio
git clone https://github.com/aliyun/infraguard.git
cd infraguard

# Compilar el binario
make build

# Opcionalmente instalar en su PATH
sudo cp infraguard /usr/local/bin/
```

## Próximos Pasos

Ahora que tiene InfraGuard instalado, proceda a la [Guía de Inicio Rápido](./quick-start) para aprender cómo usarlo.
