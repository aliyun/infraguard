---
title: Willkommen bei InfraGuard
sidebar_label: Einführung
---

# InfraGuard

**Richtlinie Definiert. Infrastruktur Gesichert.**

**Infrastructure as Code (IaC) Compliance-Vorprüfung CLI** für Alibaba Cloud ROS-Vorlagen.

Bewerten Sie Ihre ROS YAML/JSON-Vorlagen gegen Sicherheits- und Compliance-Richtlinien **vor dem Deployment**.

## Was ist InfraGuard?

InfraGuard ist ein Befehlszeilentool, das Ihnen hilft sicherzustellen, dass Ihr Infrastrukturcode Sicherheits- und Compliance-Standards erfüllt, bevor Sie in die Produktion gehen. Es verwendet Open Policy Agent (OPA) und Rego-Richtlinien, um Ihre Vorlagen zu bewerten.

## Policy as Code

InfraGuard folgt dem Prinzip **Policy as Code** - Compliance-Richtlinien als versionierte, testbare und wiederverwendbare Code-Artefakte zu behandeln.

- **Versionskontrolle** - Speichern Sie Richtlinien in Git zusammen mit Ihrem Infrastrukturcode. Verfolgen Sie Änderungen, überprüfen Sie die Historie und rollen Sie bei Bedarf zurück.
- **Automatisierte Tests** - Schreiben Sie Unit-Tests für Ihre Richtlinien mit Beispielvorlagen. Stellen Sie sicher, dass Richtlinien korrekt funktionieren, bevor Sie sie in der Produktion anwenden.
- **Code-Review** - Wenden Sie denselben Peer-Review-Prozess auf Richtlinienänderungen an wie auf Anwendungscode. Erkennen Sie Probleme frühzeitig durch Zusammenarbeit.
- **CI/CD-Integration** - Integrieren Sie Richtlinienprüfungen in Ihre CI/CD-Pipeline. Validieren Sie automatisch jede Infrastrukturänderung gegen Compliance-Anforderungen.
- **Wiederverwendbarkeit** - Kombinieren Sie einzelne Regeln zu Compliance-Paketen. Teilen Sie Richtlinien zwischen Teams und Projekten, um Konsistenz zu gewährleisten.
- **Deklarativ** - Definieren Sie *was* Compliance bedeutet mit Regos deklarativer Syntax, nicht *wie* es zu prüfen ist. Konzentrieren Sie sich auf das Ergebnis, nicht auf die Implementierung.

## Hauptfunktionen

- **Pre-Deployment-Validierung** - Erkennen Sie Compliance-Probleme, bevor sie die Produktion erreichen
- **Richtlinienpakete** - Vorgefertigte Compliance-Pakete (MLPS, ISO 27001, PCI-DSS, etc.)
- **Internationalisierung** - Vollständige Unterstützung für 7 Sprachen (Englisch, Chinesisch, Spanisch, Französisch, Deutsch, Japanisch, Portugiesisch)
- **Mehrere Ausgabeformate** - Tabellen-, JSON- und HTML-Berichte
- **Erweiterbar** - Schreiben Sie benutzerdefinierte Richtlinien in Rego
- **Schnell** - In Go entwickelt für Geschwindigkeit und Effizienz

## Unterstützte Anbieter

- **Aliyun (Alibaba Cloud)** - Hunderte von Regeln und Dutzende von Compliance-Paketen

## Schnelles Beispiel

```bash
# Scannen einer Vorlage mit einem Compliance-Paket
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Scannen mit spezifischen Regeln
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# HTML-Bericht generieren
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## Loslegen

Bereit, die Compliance Ihrer Infrastruktur zu verbessern? Schauen Sie sich unseren [Schnellstart-Leitfaden](./getting-started/quick-start) an, um zu beginnen.

## Richtlinienbibliothek

Durchsuchen Sie unsere umfassende [Richtlinienreferenz](./policies/aliyun/rules), um alle verfügbaren Regeln und Compliance-Pakete zu sehen.
