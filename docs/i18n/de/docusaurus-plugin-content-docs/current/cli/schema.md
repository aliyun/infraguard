---
title: infraguard schema
---

# infraguard schema

Verwalten Sie das ROS-Ressourcentyp-Schema, das vom LSP-Server verwendet wird.

## Unterbefehle

### update

Holen Sie das neueste ROS-Ressourcentyp-Schema von der Alibaba Cloud ROS API und speichern Sie es lokal:

```bash
infraguard schema update
```

## Beschreibung

Der Befehl `schema` verwaltet das ROS-Ressourcentyp-Schema, das der LSP-Server für Auto-Vervollständigung, Validierung und Hover-Dokumentation verwendet. Das Schema enthält Definitionen für alle ROS-Ressourcentypen, ihre Eigenschaften, Typen und Einschränkungen.

### Voraussetzungen

Der Unterbefehl `schema update` erfordert Alibaba Cloud-Anmeldedaten. Konfigurieren Sie diese mit einer der folgenden Optionen:

1. **Umgebungsvariablen**:
   ```bash
   export ALIBABA_CLOUD_ACCESS_KEY_ID="your-access-key-id"
   export ALIBABA_CLOUD_ACCESS_KEY_SECRET="your-access-key-secret"
   ```

2. **Aliyun CLI-Konfiguration**:
   ```bash
   aliyun configure
   ```

## Beispiele

### Schema aktualisieren

```bash
infraguard schema update
```

Ausgabe:
```
Updating ROS resource type schema...
Schema updated successfully (350 resource types)
```

## Exit-Codes

- `0`: Erfolg
- `1`: Fehler (z. B. fehlende Anmeldedaten, Netzwerkfehler)
