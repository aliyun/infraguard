---
title: Häufig Gestellte Fragen
---

# Häufig Gestellte Fragen

## Allgemein

### Was ist InfraGuard?

InfraGuard ist ein Befehlszeilentool, das Infrastructure as Code (IaC)-Vorlagen gegen Compliance-Richtlinien vor dem Deployment validiert. Es hilft, Sicherheits- und Compliance-Probleme früh im Entwicklungszyklus zu erkennen.

### Welche Cloud-Anbieter werden unterstützt?

Derzeit unterstützt InfraGuard Alibaba Cloud (Aliyun) ROS-Vorlagen. Die Unterstützung für andere Anbieter kann in zukünftigen Versionen hinzugefügt werden.

### Ist InfraGuard kostenlos?

Ja, InfraGuard ist Open Source und unter der Apache-Lizenz 2.0 veröffentlicht.

## Verwendung

### Wie scanne ich eine Vorlage?

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

Siehe den [Schnellstart-Leitfaden](./getting-started/quick-start) für weitere Beispiele.

### Kann ich mehrere Richtlinien in einem Scan verwenden?

Ja! Verwenden Sie mehrere `-p` Flags:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip -p pack:aliyun:quick-start-compliance-pack
```

### Welche Ausgabeformate sind verfügbar?

InfraGuard unterstützt drei Formate:
- **Tabelle**: Farbige Konsolenausgabe (Standard)
- **JSON**: Maschinenlesbar für CI/CD
- **HTML**: Interaktiver Bericht

### Wie ändere ich die Sprache?

Verwenden Sie das `--lang` Flag oder setzen Sie es permanent:

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang de
# Oder permanent setzen
infraguard config set lang de
```

InfraGuard unterstützt 7 Sprachen:
- `en` - English (Englisch)
- `zh` - Chinese (中文)
- `es` - Spanish (Spanisch)
- `fr` - French (Französisch)
- `de` - German (Deutsch)
- `ja` - Japanese (日本語)
- `pt` - Portuguese (Portugiesisch)

## Richtlinien

### Wo werden Richtlinien gespeichert?

Richtlinien sind in der Binärdatei eingebettet. Sie können auch benutzerdefinierte Richtlinien in `~/.infraguard/policies/` speichern.

### Wie aktualisiere ich Richtlinien?

```bash
infraguard policy update
```

### Kann ich benutzerdefinierte Richtlinien schreiben?

Ja! Richtlinien werden in Rego (Open Policy Agent-Sprache) geschrieben. Siehe den [Entwicklungsleitfaden](./development/writing-rules).

### Wie validiere ich meine benutzerdefinierte Richtlinie?

```bash
infraguard policy validate my-rule.rego
```
