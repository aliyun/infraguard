---
title: Configuración
---

# Configuración

InfraGuard almacena la configuración en `~/.infraguard/config.yaml`.

## Gestión de Configuración

### Establecer un Valor

```bash
infraguard config set lang es
```

### Obtener un Valor

```bash
infraguard config get lang
```

### Listar Todas las Configuraciones

```bash
infraguard config list
```

### Eliminar un Valor

```bash
infraguard config unset lang
```

## Configuraciones Disponibles

### Idioma (`lang`)

Establezca el idioma de salida predeterminado:

```bash
infraguard config set lang zh  # Chinese (中文)
infraguard config set lang en  # English (Inglés)
infraguard config set lang es  # Spanish (Español)
infraguard config set lang fr  # French (Francés)
infraguard config set lang de  # German (Alemán)
infraguard config set lang ja  # Japanese (日本語)
infraguard config set lang pt  # Portuguese (Portugués)
```

InfraGuard soporta 7 idiomas: `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. El predeterminado se detecta automáticamente según la configuración regional de su sistema.

## Archivo de Configuración

El archivo de configuración se encuentra en `~/.infraguard/config.yaml`:

```yaml
lang: es
```

Puede editar este archivo directamente si lo prefiere.
