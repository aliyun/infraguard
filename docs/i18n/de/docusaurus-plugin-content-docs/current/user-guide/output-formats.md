---
title: Ausgabeformate
---

# Ausgabeformate

InfraGuard unterstützt drei Ausgabeformate: Tabelle, JSON und HTML.

## Tabellenformat

Standardformat mit farbcodierter Konsolenausgabe. Am besten für interaktive Nutzung.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

## JSON-Format

Maschinenlesbares Format für Automatisierung und CI/CD-Pipelines.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

## HTML-Format

Interaktiver Bericht mit Filter- und Suchfunktionen.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Für detaillierte Beispiele siehe [Vorlagen Scannen](./scanning-templates).
