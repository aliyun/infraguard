---
title: Schnellstart
---

# Schnellstart

Diese Anleitung hilft Ihnen, in nur wenigen Minuten mit InfraGuard zu beginnen.

## Schritt 1: Erstellen Sie eine Beispiel-ROS-Vorlage

Erstellen Sie eine Datei namens `template.yaml` mit folgendem Inhalt:

```yaml
ROSTemplateFormatVersion: '2015-09-01'
Description: Sample ECS instance

Resources:
  MyECS:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      ImageId: 'centos_7'
      InstanceType: 'ecs.t5-lc1m1.small'
      AllocatePublicIP: true
      SecurityGroupId: 'sg-xxxxx'
      VpcId: 'vpc-xxxxx'
      VSwitchId: 'vsw-xxxxx'
```

## Schritt 2: Führen Sie Ihren Ersten Scan Durch

Scannen Sie die Vorlage mit einer integrierten Regel:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-and-anyip
```

Sie sollten eine Ausgabe sehen, die anzeigt, dass der ECS-Instanz eine öffentliche IP zugewiesen wurde, was ein Sicherheitsproblem darstellt.

## Schritt 3: Verwenden Sie ein Compliance-Paket

Anstatt einzelner Regeln können Sie mit einem gesamten Compliance-Paket scannen:

```bash
infraguard scan template.yaml -p pack:aliyun:security-group-best-practice
```

## Schritt 4: Generieren Sie einen Bericht

InfraGuard unterstützt mehrere Ausgabeformate:

### Tabellenformat (Standard)

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

### JSON-Format

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

### HTML-Bericht

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Öffnen Sie `report.html` in Ihrem Browser, um einen interaktiven Bericht anzuzeigen.

## Schritt 5: Verfügbare Richtlinien Auflisten

Um alle verfügbaren Regeln und Pakete anzuzeigen:

```bash
# Alle Richtlinien auflisten
infraguard policy list

# Details zu einer bestimmten Regel abrufen
infraguard policy get rule:aliyun:ecs-instance-no-public-ip

# Details zu einem Compliance-Paket abrufen
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

## Häufige Anwendungsfälle

### Scannen mit Mehreren Richtlinien

Sie können mehrere Richtlinien in einem einzigen Scan anwenden:

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

### Spracheinstellung

InfraGuard unterstützt 7 Sprachen:

```bash
# Deutsche Ausgabe
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang de

# Englische Ausgabe
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang en

# Andere unterstützte Sprachen: zh (Chinesisch), es (Spanisch), fr (Französisch), ja (Japanisch), pt (Portugiesisch)
```

Sie können die Sprache auch permanent festlegen:

```bash
infraguard config set lang de
```

Unterstützte Sprachcodes: `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. Der Standardwert wird automatisch basierend auf Ihrer Systemeinstellung erkannt.

## Nächste Schritte

- **Mehr Erfahren**: Lesen Sie das [Benutzerhandbuch](../user-guide/scanning-templates) für detaillierte Informationen
- **Richtlinien Erkunden**: Durchsuchen Sie die [Richtlinienreferenz](../policies/aliyun/rules), um alle verfügbaren Regeln und Pakete zu sehen
- **Benutzerdefinierte Richtlinien Schreiben**: Schauen Sie sich den [Entwicklungsleitfaden](../development/writing-rules) an, um Ihre eigenen Regeln zu erstellen

## Hilfe Erhalten

Wenn Sie auf Probleme stoßen:

1. Überprüfen Sie die [FAQ](../faq)-Seite
2. Überprüfen Sie Fehlermeldungen sorgfältig - sie enthalten normalerweise hilfreiche Hinweise
3. Melden Sie Probleme auf [GitHub](https://github.com/aliyun/infraguard/issues)
