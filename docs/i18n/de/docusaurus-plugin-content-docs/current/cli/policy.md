---
title: infraguard policy
---

# infraguard policy

Compliance-Richtlinien verwalten.

## Unterbefehle

### list

Alle verfügbaren Richtlinien auflisten:
```bash
infraguard policy list
```

### get

Details einer bestimmten Richtlinie abrufen:
```bash
infraguard policy get rule:aliyun:ecs-instance-no-public-ip
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### update

Richtlinienbibliothek aktualisieren:
```bash
infraguard policy update
```

### new

Eine neue benutzerdefinierte Regel gerüsten (Rego-Skelett + Test-Fixtures):
```bash
# Eine Regel für ROS und Terraform generieren
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance

# Ein Compliance-Pack-Skelett generieren
infraguard policy new --pack my-team-baseline
```

Die generierten Dateien liegen unter `--dir` (Standard `./policies`) und können direkt mit `infraguard scan -p ./policies <template>` und `infraguard policy test` verwendet werden. Siehe [Benutzerdefinierte Regeln Erstellen](../development/scaffolding-rules).

| Flag | Beschreibung | Standard |
| --- | --- | --- |
| `--iac` | Ziel-IaC: `ros`, `terraform` oder `both` | `both` |
| `--severity` | `high`, `medium` oder `low` | `medium` |
| `--resource-type` | ROS-Ressourcentyp (wiederholbar) | — |
| `--tf-resource-type` | Terraform-Ressourcentyp (wiederholbar) | — |
| `--dir` | Ausgabe-Wurzelverzeichnis | `./policies` |
| `--name-en` / `--name-zh` | Regelname | Regel-ID |
| `--desc-en` / `--desc-zh` | Regelbeschreibung | `TODO` |
| `--no-test` | Keine Test-Fixtures generieren | `false` |
| `--force` | Vorhandene Dateien überschreiben | `false` |
| `--pack` | Ein Pack-Skelett mit der angegebenen ID generieren | — |

### test

Verhaltenstests für Regeln anhand ihrer Fixtures ausführen:
```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule my-rule --iac terraform
infraguard policy test --dir ./policies --format json
```

Für jede Regel werden die Fixtures unter `<dir>/testdata/aliyun/rules/<rule>/` ausgewertet: `compliant`-Fixtures dürfen **keine** Verstöße gegen die Regel erzeugen und `violation`-Fixtures müssen **mindestens einen** erzeugen. Der Exit-Code ist `0`, wenn alle Fälle bestehen, `1` bei einem Fehler und `2`, wenn keine Fixtures gefunden werden (es sei denn, `--allow-empty`). Siehe [Regeln Testen](../development/scaffolding-rules).

| Flag | Beschreibung | Standard |
| --- | --- | --- |
| `--dir` | Wurzelverzeichnis mit `rules/` und `testdata/` | `./policies` |
| `--rule` | Nur die angegebene Regel-ID testen (wiederholbar) | alle |
| `--iac` | Zu testende IaC: `ros`, `terraform` oder `both` | `both` |
| `--format` | Ausgabeformat: `table` oder `json` | `table` |
| `--allow-empty` | Mit `0` beenden, auch wenn keine Fixtures gefunden werden | `false` |

### validate

Benutzerdefinierte Richtlinien validieren:
```bash
infraguard policy validate my-rule.rego
infraguard policy validate ./policies/ --lang de
```

### format

Richtliniendateien formatieren:
```bash
infraguard policy format rule.rego
infraguard policy format rule.rego --write
infraguard policy format rule.rego --diff
```

### clean

Benutzer-Richtlinienverzeichnis bereinigen:
```bash
infraguard policy clean              # Interaktiver Modus mit Bestätigung
infraguard policy clean --force      # Bestätigung überspringen
infraguard policy clean -f           # Kurzes Flag
```

Entfernt alle Richtlinien aus `~/.infraguard/policies/`. Betrifft keine integrierten Richtlinien oder Arbeitsbereichsrichtlinien.

Für weitere Details siehe [Richtlinien Verwalten](../user-guide/managing-policies).
