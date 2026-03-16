---
title: Editor-Integration
---

# Editor-Integration

InfraGuard bietet Editor-Integration über einen eingebauten Language Server Protocol (LSP)-Server und eine VS Code-Erweiterung und ermöglicht intelligente Bearbeitungsunterstützung für ROS-Vorlagen.

## VS Code-Erweiterung

### Installation

Installieren Sie die **InfraGuard**-Erweiterung aus dem [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=AlibabaCloudROS.infraguard) oder suchen Sie nach "InfraGuard" im VS Code-Erweiterungsbereich.

Die Erweiterung erfordert, dass die `infraguard`-CLI installiert und in Ihrer PATH verfügbar ist. Siehe [Installation](../getting-started/installation) für Details.

### Funktionen

#### Auto-Vervollständigung

Kontextbezogene Vervollständigungen über die gesamte Vorlagenstruktur:

- **Ressourcentypen** — Alle ALIYUN::*-Ressourcentyp-Identifikatoren
- **Eigenschaften** — Ressourceneigenschaften mit Typinformationen, erforderliche Eigenschaften priorisiert
- **Intrinsische Funktionen** — `Fn::Join`, `Fn::Sub`, `Fn::Select` und mehr
- **Ref/GetAtt-Ziele** — Verweise auf Parameter, Ressourcen und deren Attribute
- **Parameterdefinitionen** — Type, Default, AllowedValues und andere Parametereigenschaften
- **Abschnitte auf oberster Ebene** — ROSTemplateFormatVersion, Parameters, Resources, Outputs usw.

Wenn Sie einen Ressourcentyp eingeben, wird ein `Properties`-Block mit allen erforderlichen Schlüsseln automatisch eingefügt.

#### Echtzeit-Diagnose

Validiert Ihre Vorlage während der Eingabe:

- Fehlende oder ungültige `ROSTemplateFormatVersion`
- Unbekannte Ressourcentypen
- Fehlende erforderliche Eigenschaften
- Typinkompatibilitäten bei Eigenschaftswerten
- Ungültige Parameterdefinitionen
- Doppelte YAML-Schlüssel
- Unbekannte Schlüssel mit „Meinten Sie?“-Vorschlägen

#### Hover-Dokumentation

Bewegen Sie den Mauszeiger über Elemente, um kontextbezogene Dokumentation zu sehen:

- **Ressourcentypen** — Beschreibung und Link zur offiziellen Dokumentation
- **Eigenschaften** — Typ, Einschränkungen, erforderlich oder optional, Update-Verhalten
- **Intrinsische Funktionen** — Syntax und Verwendungsbeispiele

#### Syntaxhervorhebung

Erweiterte Syntaxhervorhebung für ROS-spezifische Elemente:

- `!Ref`, `Fn::Join` und andere intrinsische Funktionen
- `ALIYUN::*::*`-Ressourcentyp-Identifikatoren

### Unterstützte Dateitypen

| Pattern | Detection |
|---------|-----------|
| `*.ros.yaml` / `*.ros.yml` | Automatisch als ROS-Vorlagen erkannt |
| `*.ros.json` | Automatisch als ROS-Vorlagen erkannt |
| `*.yaml` / `*.json` | Erkannt über `ROSTemplateFormatVersion` im Inhalt |

### Befehle

| Command | Description |
|---------|-------------|
| **InfraGuard: Update ROS Schema** | Neuestes Ressourcentyp-Schema von der ROS-API abrufen |

### ROS-Schema aktualisieren

Die Erweiterung enthält ein eingebautes Schema für ROS-Ressourcentypen. Zur Aktualisierung mit den neuesten Ressourcentyp-Definitionen:

1. Öffnen Sie die Befehlspalette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Führen Sie **InfraGuard: Update ROS Schema** aus

Dies erfordert konfigurierte Alibaba Cloud-Anmeldedaten. Siehe [`infraguard schema update`](../cli/schema) für die Anmeldedaten-Konfiguration.

## LSP-Server

Der LSP-Server kann mit jedem Editor integriert werden, der das Language Server Protocol unterstützt.

### Server starten

```bash
infraguard lsp
```

Der Server kommuniziert über stdio (Standard-Ein-/Ausgabe).

### Editor-Konfiguration

Für andere Editoren als VS Code konfigurieren Sie den LSP-Client so, dass er:

1. Den Server mit `infraguard lsp` startet
2. stdio als Transport verwendet
3. Mit YAML- und JSON-Dateitypen verknüpft ist

Siehe [`infraguard lsp`](../cli/lsp) für weitere Details.
