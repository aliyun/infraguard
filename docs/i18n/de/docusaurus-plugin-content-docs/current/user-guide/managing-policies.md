---
title: Richtlinien Verwalten
---

# Richtlinien Verwalten

Erfahren Sie, wie Sie Richtlinien in InfraGuard entdecken, verwalten und aktualisieren.

## Richtlinien Auflisten

### Alle Richtlinien Auflisten

Alle verfügbaren Regeln und Pakete anzeigen:

```bash
infraguard policy list
```

Dies zeigt:
- Alle integrierten Regeln
- Alle Compliance-Pakete
- Benutzerdefinierte Richtlinien (falls vorhanden)

### Nach Anbieter Filtern

Derzeit unterstützt InfraGuard Aliyun-Richtlinien. Zukünftige Versionen werden zusätzliche Anbieter unterstützen.

## Richtliniendetails

### Regelinformationen Abrufen

Detaillierte Informationen zu einer bestimmten Regel anzeigen:

```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
```

Die Ausgabe enthält:
- Regel-ID und Name
- Schweregrad
- Beschreibung
- Grund für den Fehler
- Empfehlung
- Betroffene Ressourcentypen

### Paketinformationen Abrufen

Compliance-Paketdetails anzeigen:

```bash
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

Die Ausgabe enthält:
- Paket-ID und Name
- Beschreibung
- Liste der enthaltenen Regeln

## Richtlinien Aktualisieren

InfraGuard enthält integrierte Richtlinien, aber Sie können auch die neueste Richtlinienbibliothek herunterladen:

```bash
infraguard policy update
```

Dies lädt Richtlinien nach `~/.infraguard/policies/` herunter, was Vorrang vor integrierten Richtlinien hat.

## Richtlinien Bereinigen

Um heruntergeladene Richtlinien aus Ihrem Benutzerverzeichnis zu entfernen:

```bash
infraguard policy clean
```

Dieser Befehl:
- Entfernt alle Richtlinien aus `~/.infraguard/policies/`
- Fordert standardmäßig eine Bestätigung an
- Betrifft keine integrierten Richtlinien (sie bleiben verfügbar)
- Betrifft keine Arbeitsbereichsrichtlinien in `.infraguard/policies/`

### Erzwungenes Bereinigen (Ohne Bestätigung)

Für Skripte oder nicht-interaktive Umgebungen:

```bash
infraguard policy clean --force
# oder
infraguard policy clean -f
```

### Richtlinienladepriorität

InfraGuard lädt Richtlinien aus drei Quellen mit der folgenden Priorität (von höchster zu niedrigster):

1. **Arbeitsbereichslokale Richtlinien**: `.infraguard/policies/` (relativ zum aktuellen Arbeitsverzeichnis)
2. **Benutzerlokale Richtlinien**: `~/.infraguard/policies/`
3. **Integrierte Richtlinien**: In die Binärdatei eingebettet (Fallback)

Richtlinien mit derselben ID aus Quellen mit höherer Priorität überschreiben solche mit niedrigerer Priorität. Dies ermöglicht:
- **Projektspezifische Richtlinien**: Definieren Sie benutzerdefinierte Regeln in `.infraguard/policies/`, die mit Ihrem Projekt versionskontrolliert sind
- **Benutzeranpassungen**: Überschreiben Sie integrierte Richtlinien global über `~/.infraguard/policies/`
- **Nahtloser Fallback**: Integrierte Richtlinien funktionieren ohne Konfiguration

## Benutzerdefinierte Richtlinien Validieren

Bevor Sie benutzerdefinierte Richtlinien verwenden, validieren Sie sie:

```bash
infraguard policy validate ./my-custom-rule.rego
```

Dies überprüft:
- Rego-Syntax
- Erforderliche Metadaten (`rule_meta` oder `pack_meta`)
- Angemessene Deny-Regelstruktur

### Validierungsoptionen

```bash
# Einzelne Datei validieren
infraguard policy validate rule.rego

# Verzeichnis validieren
infraguard policy validate ./policies/

# Ausgabesprache angeben
infraguard policy validate rule.rego --lang de
```

## Richtlinien Formatieren

Formatieren Sie Ihre Richtliniendateien mit dem OPA-Formatierer:

```bash
# Formatierte Ausgabe anzeigen
infraguard policy format rule.rego

# Änderungen zurück in die Datei schreiben
infraguard policy format rule.rego --write

# Diff der Änderungen anzeigen
infraguard policy format rule.rego --diff
```

## Richtlinienorganisation

### Integrierte Richtlinien

Befinden sich in der Binärdatei unter:
- `policies/aliyun/rules/` - Einzelne Regeln
- `policies/aliyun/packs/` - Compliance-Pakete
- `policies/aliyun/lib/` - Hilfsbibliotheken

### Benutzerdefinierte Richtlinien

#### Arbeitsbereichslokale Richtlinien (Projektspezifisch)

Speichern Sie projektspezifische Richtlinien in Ihrem Projektverzeichnis:
- `.infraguard/policies/<provider>/rules/` - Projektspezifische Regeln
- `.infraguard/policies/<provider>/packs/` - Projektspezifische Pakete
- `.infraguard/policies/<provider>/lib/` - Projektspezifische Hilfsbibliotheken

Diese Richtlinien werden automatisch geladen, wenn InfraGuard-Befehle aus dem Projektverzeichnis ausgeführt werden, und können zusammen mit Ihren IaC-Vorlagen versionskontrolliert werden.

#### Benutzerlokale Richtlinien (Global)

Speichern Sie globale benutzerdefinierte Richtlinien in Ihrem Home-Verzeichnis:
- `~/.infraguard/policies/<provider>/rules/` - Globale benutzerdefinierte Regeln
- `~/.infraguard/policies/<provider>/packs/` - Globale benutzerdefinierte Pakete
- `~/.infraguard/policies/<provider>/lib/` - Globale benutzerdefinierte Hilfsbibliotheken

Diese Richtlinien sind für alle Projekte verfügbar und können integrierte Richtlinien überschreiben.
