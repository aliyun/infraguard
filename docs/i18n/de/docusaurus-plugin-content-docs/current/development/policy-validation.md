---
title: Richtlinienvalidierung
---

# Richtlinienvalidierung

Validiere Ihre benutzerdefinierten Richtlinien, bevor Sie sie verwenden.

## Validierungsbefehl

```bash
infraguard policy validate <path>
```

## Was Wird Validiert

- Rego-Syntax
- Erforderliche Metadaten (`rule_meta` oder `pack_meta`)
- Angemessene Deny-Regelstruktur
- i18n-String-Format

## Beispiele

```bash
# Einzelne Datei validieren
infraguard policy validate rule.rego

# Verzeichnis validieren
infraguard policy validate ./policies/

# Mit Sprachoption
infraguard policy validate rule.rego --lang de
```

Für weitere Informationen siehe [Richtlinien Verwalten](../user-guide/managing-policies).
