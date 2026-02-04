---
title: Vorlagen Scannen
---

# Vorlagen Scannen

Der Befehl `infraguard scan` bewertet Ihre ROS-Vorlagen gegen Compliance-Richtlinien.

## Grundlegende Verwendung

```bash
infraguard scan <template> -p <policy>
```

### Erforderliche Argumente

- `<template>`: Pfad zu Ihrer ROS-Vorlagendatei (YAML oder JSON) - Positionsargument

### Erforderliche Flags

- `-p, --policy <id>`: Anzuwendende Richtlinie (kann mehrfach verwendet werden)

### Optionale Flags

- `--format <format>`: Ausgabeformat (`table`, `json`, oder `html`)
- `-o, --output <file>`: Ausgabedateipfad (für HTML- und JSON-Formate)
- `--lang <lang>`: Ausgabesprache (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`)
- `-m, --mode <mode>`: Scan-Modus: `static` für lokale Analyse oder `preview` für ROS PreviewStack API (Standard: `static`)
- `-i, --input <value>`: Parameterwerte im Format `key=value`, JSON-Format oder Dateipfad (kann mehrfach angegeben werden)

## Richtlinientypen

Sie können mit verschiedenen Richtlinientypen scannen:

### 1. Einzelne Regeln

Scannen mit einer spezifischen Compliance-Regel:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip
```

### 2. Compliance-Pakete

Scannen mit einem vordefinierten Compliance-Paket:

```bash
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### 3. Wildcard-Mustervergleich

Verwenden Sie Wildcard-Muster (`*`), um mehrere Regeln oder Pakete zu finden:

**Alle Regeln finden:**
```bash
infraguard scan template.yaml -p "rule:*"
```

**Regeln nach Präfix finden:**
```bash
infraguard scan template.yaml -p "rule:aliyun:ecs-*"
```

### 4. Benutzerdefinierte Richtliniendateien

Scannen mit Ihrer eigenen Rego-Richtliniendatei:

```bash
infraguard scan template.yaml -p ./my-custom-rule.rego
```

### 5. Richtlinienverzeichnisse

Scannen mit allen Richtlinien in einem Verzeichnis:

```bash
infraguard scan template.yaml -p ./my-policies/
```

## Scan-Modi

InfraGuard unterstützt zwei Scan-Modi:

### Statischer Modus (Standard)

Führt eine lokale statische Analyse der Vorlage durch, ohne Zugriff auf den Cloud-Anbieter zu benötigen:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode static
```

Dieser Modus analysiert die Vorlagenstruktur und Ressourcenkonfigurationen lokal. Er ist schnell und benötigt keine Cloud-Anmeldedaten, unterstützt aber möglicherweise nicht alle ROS-Funktionen (siehe [ROS-Funktionsunterstützung](./ros-features)).

### Preview-Modus

Verwendet die ROS PreviewStack API, um Vorlagen mit tatsächlicher Cloud-Anbieterbewertung zu validieren:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview
```

Der Preview-Modus bietet eine genauere Analyse für Funktionen, die Laufzeitbewertung erfordern (wie `Fn::GetAtt`, `Fn::GetAZs`, etc.). Dieser Modus erfordert, dass ROS-Anmeldedaten konfiguriert sind.

Für Vorlagen, die Funktionen verwenden, die von der statischen Analyse nicht unterstützt werden, empfehlen wir die Verwendung von `--mode preview` für genauere Ergebnisse.

## Mehrere Richtlinien

Wenden Sie mehrere Richtlinien in einem einzigen Scan an:

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

## Ausgabeformate

### Tabellenformat (Standard)

Zeigt Ergebnisse in einer farbcodierten Tabelle:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

Beispielausgabe:

```
┌──────────────────────┬────────────┬──────────────┬──────────────────────┬─────────────────────────┐
│ RULE ID              │ SEVERITY   │ RESOURCE     │ REASON               │ RECOMMENDATION          │
├──────────────────────┼────────────┼──────────────┼──────────────────────┼─────────────────────────┤
│ ecs-no-public-ip     │ high       │ MyECS        │ Public IP allocated  │ Use NAT Gateway instead │
└──────────────────────┴────────────┴──────────────┴──────────────────────┴─────────────────────────┘
```

### JSON-Format

Maschinenlesbares Format für CI/CD-Integration:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

Ausgabe:

```json
{
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "violations": [
    {
      "rule_id": "ecs-no-public-ip",
      "severity": "high",
      "resource_id": "MyECS",
      "reason": "Public IP allocated",
      "recommendation": "Use NAT Gateway instead"
    }
  ]
}
```

### HTML-Bericht

Interaktiver HTML-Bericht mit Filter- und Suchfunktionen:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Öffnen Sie `report.html` in Ihrem Browser für eine interaktive Erfahrung.

## Exit-Codes

InfraGuard verwendet verschiedene Exit-Codes, um Scan-Ergebnisse anzuzeigen:

- `0`: Keine Verstöße gefunden
- `1`: Verstöße gefunden
- `2`: Verstöße mit hoher Schwere gefunden

Dies ist nützlich für CI/CD-Pipelines:

```bash
#!/bin/bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
if [ $? -eq 2 ]; then
  echo "Verstöße mit hoher Schwere gefunden! Deployment blockiert."
  exit 1
fi
```

## Beispiele

### Beispiel 1: Sicherheitsaudit

```bash
infraguard scan production.yaml \
  -p pack:aliyun:security-group-best-practice \
  -p pack:aliyun:resource-protection-best-practice \
  --format html \
  -o security-audit.html
```

### Beispiel 2: Compliance-Prüfung

```bash
infraguard scan template.yaml \
  -p pack:aliyun:mlps-level-3-pre-check-compliance-pack \
  -p pack:aliyun:iso-27001-compliance \
  --lang de \
  --format json \
  -o compliance-report.json
```

### Beispiel 3: CI/CD-Integration

```bash
# In Ihrer CI/CD-Pipeline
infraguard scan "${TEMPLATE_FILE}" \
  -p pack:aliyun:quick-start-compliance-pack \
  --format json \
  --lang en
```

### Beispiel 4: Preview-Modus mit Parametern

Scannen mit Preview-Modus mit Vorlagenparametern:

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input InstanceType=ecs.c6.large \
  --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd
```

Sie können auch Parameter aus einer JSON-Datei bereitstellen:

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input parameters.json
```

## Tipps

1. **Beginnen Sie mit dem Quick-Start-Paket**: Verwenden Sie `pack:aliyun:quick-start-compliance-pack` für wesentliche Prüfungen
2. **Verwenden Sie Mehrere Pakete**: Kombinieren Sie mehrere Pakete für umfassende Abdeckung
3. **Berichte Speichern**: Verwenden Sie HTML-Format für Stakeholder-Berichte, JSON für Automatisierung
4. **Sprache Einmal Setzen**: Verwenden Sie `infraguard config set lang de`, um das Flag `--lang` nicht wiederholen zu müssen

## Nächste Schritte

- Erfahren Sie mehr über [Richtlinien Verwalten](./managing-policies)
- Erkunden Sie [Ausgabeformate](./output-formats) im Detail
- Konfigurieren Sie [Konfiguration](./configuration)
