---
title: Waiver
---

# Waiver (Unterdrückungen)

Wenn ein Verstoß bekannt und akzeptiert ist — eine Legacy-Ressource, ein
anderweitig abgemildertes Risiko, eine vorübergehende Ausnahme — können Sie ihn
**waiven**, anstatt die Regel vollständig zu deaktivieren oder InfraGuard zu
umgehen. Ein Waiver ist eine explizite, prüfbare Entscheidung: Er trägt immer eine
Begründung und idealerweise ein Ablaufdatum.

InfraGuard verwirft einen waived Fund niemals stillschweigend. Aktive Waiver
werden in der Standardausgabe ausgeblendet, aber in der Zusammenfassung gezählt;
abgelaufene Waiver tauchen wieder als echte Verstöße auf, damit sie erneuert werden.

## Zwei Wege zum Waiven

### 1. Inline-Kommentare

Annotieren Sie die Ressource direkt in der Vorlage. Funktioniert sowohl für ROS
(YAML) als auch für Terraform (HCL):

```yaml
Resources:
  # infraguard:ignore=oss-bucket-public-read-prohibited reason="legacy bucket, migrating 2026Q4" expires=2026-12-31
  LegacyBucket:
    Type: ALIYUN::OSS::Bucket
    Properties:
      AccessControl: public-read
```

```hcl
resource "alicloud_oss_bucket" "legacy" {
  # infraguard:ignore=oss-bucket-public-read-prohibited reason="legacy bucket" expires=2026-12-31
  bucket = "legacy"
  acl    = "public-read"
}
```

Syntax:

```
infraguard:ignore=<rule-id>[,<rule-id>...] reason="..." [expires=YYYY-MM-DD]
infraguard:ignore=*  reason="..."     # alle Regeln für diese Ressource unterdrücken
```

Eine Direktive, die auf oder direkt über einer Ressource platziert ist, gilt für
diese Ressource. Eine Direktive ohne `reason` wird ignoriert.

### 2. Zentrale Waiver-Datei

Für Batch- oder verwaltete Waiver committen Sie eine `.infraguard/waivers.yaml`
in Ihr Repository (sie durchläuft das Code-Review wie jede andere Änderung):

```yaml
version: 1
waivers:
  - rule: oss-bucket-public-read-prohibited
    resource: "LegacyBucket"          # exakte ID oder Glob, z. B. "legacy-*"
    files: ["envs/legacy/**"]          # optionale Datei-Globs (unterstützt **)
    reason: "Legacy resource, approved in CAB-1234"
    expires: 2026-09-30
    owner: alice@example.com

  - rule: rds-instance-enabled-tde
    resource: "*"                      # alle passenden Ressourcen
    files: ["sandbox/**"]
    reason: "Sandbox environment does not require TDE"
    # kein expires → dauerhafter Waiver (von `waiver lint` markiert)
```

| Feld | Bedeutung | Erforderlich |
| --- | --- | --- |
| `rule` | Kurze Regel-ID oder `*` für alle Regeln | Ja |
| `resource` | Ressourcen-ID, exakt oder Glob | Nein (jede Ressource) |
| `files` | Dateipfad-Globs (`*`, `**`) | Nein (jede Datei) |
| `reason` | Begründung | Ja |
| `expires` | `YYYY-MM-DD`; leer bedeutet dauerhaft | Nein (empfohlen) |
| `owner` | Verantwortliche Person | Nein (empfohlen) |

Inline-Direktiven haben Vorrang vor Datei-Waivern für dieselbe Ressource.

## Verhalten während eines Scans

- **Aktiver** Waiver → der Verstoß wird ausgeblendet und in der Zusammenfassung als `waived` gezählt.
- **Abgelaufener** Waiver → der Verstoß wird wieder angezeigt und lässt den Build standardmäßig fehlschlagen.
- **Kein Waiver** → ein normaler Verstoß.

```bash
infraguard scan -p pack:aliyun:... template.yaml          # Waiver werden automatisch angewendet
infraguard scan ... --show-waived template.yaml           # anzeigen, was waived wurde
infraguard scan ... --no-waivers template.yaml            # vollständige Ansicht, alle Waiver ignorieren
infraguard scan ... --fail-on-expired=false template.yaml # bei abgelaufenen Waivern nicht fehlschlagen
```

Für CI kann ein Sicherheitsteam `--no-waivers` ausführen, um das Gesamtbild zu
sehen, oder die Waiver beibehalten und sich auf das standardmäßige
`--fail-on-expired` verlassen, um Erneuerungen zu erzwingen.

## Waiver verwalten

```bash
infraguard waiver list    # jeden Waiver und seinen Status anzeigen
infraguard waiver lint    # fehlende Begründungen, unbekannte Regeln, abgelaufene Einträge finden
```

Fügen Sie `waiver lint` zu Pre-Commit oder CI hinzu, damit die Waiver-Datei selbst
gesund bleibt. Siehe die [Waiver-CLI-Referenz](../cli/waiver).

## Ein Hinweis zur Sicherheit

Waiver verbergen legitim Risiken und sind daher bewusst eingeschränkt: eine
`reason` ist obligatorisch, abgelaufene Waiver schlagen standardmäßig fehl, die
JSON-Ausgabe behält waived Einträge stets für die Prüfung bei und die Datei wird
über Git geprüft. Bevorzugen Sie enge Waiver (Regel + Ressource + Datei) gegenüber
weit gefassten und setzen Sie stets ein `expires`-Datum.
