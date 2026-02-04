---
title: Richtlinienverzeichnisstruktur
---

# Richtlinienverzeichnisstruktur

InfraGuard unterstützt mehrere Richtlinienquellen mit einem klaren Prioritätssystem zum Laden von Richtlinien.

## Verzeichnisstruktur

### Standard-Richtlinienverzeichnisstruktur

Richtlinien folgen einer anbieterorientierten Verzeichnisstruktur:

```
{policy-root}/
├── {provider}/
│   ├── rules/
│   │   ├── rule1.rego            # Einzelne Regeln
│   │   └── rule2.rego
│   └── packs/
│       ├── pack1.rego            # Compliance-Pakete
│       └── pack2.rego
```

**Beispiel:**

```
.infraguard/policies/
├── solution/
│   ├── rules/
│   │   ├── metadata-ros-composer-check.rego
│   │   ├── metadata-templatetags-check.rego
│   │   ├── parameter-sensitive-noecho-check.rego
│   │   └── security-group-open-ports-except-whitelist.rego
│   └── packs/
│       └── ros-best-practice.rego
```

## Richtlinienladepriorität

InfraGuard lädt Richtlinien aus mehreren Quellen mit der folgenden Priorität (von höchster zu niedrigster):

1. **Arbeitsbereichslokale Richtlinien**: `.infraguard/policies/` (aktuelles Arbeitsverzeichnis)
2. **Benutzerlokale Richtlinien**: `~/.infraguard/policies/` (Benutzer-Home-Verzeichnis)
3. **Integrierte Richtlinien**: In die Binärdatei eingebettet

Richtlinien mit derselben ID aus Quellen mit höherer Priorität überschreiben solche mit niedrigerer Priorität.

## Arbeitsbereichslokale Richtlinien

Arbeitsbereichslokale Richtlinien werden im Verzeichnis `.infraguard/policies/` innerhalb Ihres aktuellen Arbeitsverzeichnisses gespeichert. Dies ist der Standort mit der höchsten Priorität und ideal für:

- Projektspezifische benutzerdefinierte Regeln und Pakete
- Überschreiben integrierter Richtlinien für spezifische Projekte
- Testen neuer Richtlinien, bevor sie zu benutzerlokal oder integriert befördert werden

### Verwenden von Arbeitsbereichsrichtlinien

1. Erstellen Sie die Verzeichnisstruktur:

```bash
mkdir -p .infraguard/policies/myprovider/{rules,packs}
```

2. Fügen Sie Ihre benutzerdefinierten Regeln oder Pakete zu den entsprechenden Verzeichnissen hinzu

3. Listen Sie verfügbare Richtlinien auf:

```bash
infraguard policy list
```

Ihre Arbeitsbereichsrichtlinien erscheinen mit dem ID-Format: `rule:myprovider:rule-name` oder `pack:myprovider:pack-name`

4. Verwenden Sie sie in Scans:

```bash
infraguard scan template.yml -p "pack:myprovider:my-pack"
```

## Benutzerlokale Richtlinien

Benutzerlokale Richtlinien werden in `~/.infraguard/policies/` in Ihrem Home-Verzeichnis gespeichert. Diese Richtlinien sind für alle Projekte für Ihr Benutzerkonto verfügbar.

## ID-Generierung

InfraGuard generiert automatisch Richtlinien-IDs basierend auf der Verzeichnisstruktur:

- **Regeln**: `rule:{provider}:{rule-id}`
- **Pakete**: `pack:{provider}:{pack-id}`

Wobei `{provider}` vom Namen des übergeordneten Verzeichnisses abgeleitet wird (z. B. `solution`, `aliyun`, `custom`).

## Nächste Schritte

- Lernen Sie [Regeln Schreiben](./writing-rules)
- Lernen Sie [Pakete Schreiben](./writing-packs)
- Siehe [Richtlinienvalidierung](./policy-validation)
