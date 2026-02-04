---
title: infraguard policy
---

# infraguard policy

Compliance-Richtlinien verwalten.

## Unterbefehle

### list

Alle verfügbaren Richtlinien auflisten:
```bash
infraguard policy list
```

### get

Details einer bestimmten Richtlinie abrufen:
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

Richtlinienbibliothek aktualisieren:
```bash
infraguard policy update
```

### validate

Benutzerdefinierte Richtlinien validieren:
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang de
```

### format

Richtliniendateien formatieren:
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

### clean

Benutzer-Richtlinienverzeichnis bereinigen:
```bash
infraguard policy clean              # Interaktiver Modus mit Bestätigung
infraguard policy clean --force      # Bestätigung überspringen
infraguard policy clean -f           # Kurzes Flag
```

Entfernt alle Richtlinien aus `~/.infraguard/policies/`. Betrifft keine integrierten Richtlinien oder Arbeitsbereichsrichtlinien.

Für weitere Details siehe [Richtlinien Verwalten](../user-guide/managing-policies).
