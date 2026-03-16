<div align="center">
  <img src="../assets/logo.png" alt="InfraGuard Logo" width="200"/>
</div>

# InfraGuard

**Richtlinien definiert. Infrastruktur gesichert.**

**Infrastructure as Code (IaC) Compliance Pre-Check CLI** für Alibaba Cloud ROS-Vorlagen. Bewerten Sie Ihre ROS YAML/JSON-Vorlagen gegen Sicherheits- und Compliance-Richtlinien **vor dem Deployment**.

> 💡 InfraGuard folgt dem Prinzip **Policy as Code** - Compliance-Richtlinien als versionierte, testbare und wiederverwendbare Code-Artefakte zu behandeln.

**Sprache**: [English](../README.md) | [中文](README.zh.md) | [Español](README.es.md) | [Français](README.fr.md) | Deutsch | [日本語](README.ja.md) | [Português](README.pt.md)

## ✨ Funktionen

- 🔍 **Pre-Deployment-Validierung** - Compliance-Probleme erkennen, bevor sie die Produktion erreichen
- 🎯 **Dual-Scan-Modi** - Statische Analyse oder cloud-basierte Preview-Validierung
- 📦 **Integrierte Regeln** - Umfassende Abdeckung für Aliyun-Dienste
- 🏆 **Compliance-Pakete** - MLPS, ISO 27001, PCI-DSS, SOC 2 und mehr
- ✏️ **Editor-Integration** - VS Code-Erweiterung mit Auto-Vervollständigung, Echtzeit-Diagnose und Hover-Dokumentation für ROS-Templates
- 🌍 **Mehrsprachige Unterstützung** - Verfügbar in 7 Sprachen (Deutsch, Englisch, Chinesisch, Spanisch, Französisch, Japanisch, Portugiesisch)
- 🎨 **Mehrere Ausgabeformate** - Tabellen-, JSON- und interaktive HTML-Berichte
- 🔧 **Erweiterbar** - Schreiben Sie benutzerdefinierte Richtlinien in Rego (Open Policy Agent)
- ⚡ **Schnell** - In Go entwickelt für Geschwindigkeit und Effizienz

## 🚀 Schnellstart

### Installation

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

Oder laden Sie vorkompilierte Binärdateien von [GitHub Releases](https://github.com/aliyun/infraguard/releases) herunter.

### Grundlegende Verwendung

```bash
# Scannen mit einem Compliance-Paket
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Scannen mit einer bestimmten Regel
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Scannen mit Wildcard-Muster (alle Regeln)
infraguard scan template.yaml -p "rule:*"

# Scannen mit Wildcard-Muster (alle ECS-Regeln)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# HTML-Bericht generieren
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## 📚 Dokumentation

Für detaillierte Dokumentation besuchen Sie bitte unsere [Dokumentationsseite](https://aliyun.github.io/infraguard/de/)

- **[Erste Schritte](https://aliyun.github.io/infraguard/de/docs/getting-started/installation)** - Installations- und Schnellstart-Anleitung
- **[Benutzerhandbuch](https://aliyun.github.io/infraguard/de/docs/user-guide/scanning-templates)** - Erfahren Sie, wie Sie Vorlagen scannen und Richtlinien verwalten
- **[Richtlinienreferenz](https://aliyun.github.io/infraguard/de/docs/policies/aliyun/rules)** - Durchsuchen Sie alle verfügbaren Regeln und Compliance-Pakete
- **[Entwicklungsleitfaden](https://aliyun.github.io/infraguard/de/docs/development/writing-rules)** - Schreiben Sie benutzerdefinierte Regeln und Pakete
- **[CLI-Referenz](https://aliyun.github.io/infraguard/de/docs/cli/scan)** - Dokumentation der Befehlszeilenschnittstelle
- **[FAQ](https://aliyun.github.io/infraguard/de/docs/faq)** - Häufig gestellte Fragen
