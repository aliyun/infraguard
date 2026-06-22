---
title: infraguard waiver
---

# infraguard waiver

Regel-Waiver (Unterdrückungen) verwalten. Mit Waivern können Sie bestimmte
Verstöße bewusst mit einer Begründung und einem optionalen Ablaufdatum unterdrücken.
Konzepte und das Waiver-Dateiformat finden Sie im [Waiver-Leitfaden](../user-guide/waivers).

## Unterbefehle

### list

Alle Waiver und ihren Status auflisten (aktiv / abgelaufen / dauerhaft):
```bash
infraguard waiver list
infraguard waiver list --waivers ./path/to/waivers.yaml
```

### lint

Die Waiver-Datei validieren — meldet fehlende Begründungen, unbekannte Regeln,
ungültige oder abgelaufene Daten:
```bash
infraguard waiver lint
infraguard waiver lint --rules-dir ./policies/rules   # erkennt auch benutzerdefinierte Regeln
```

`lint` beendet sich mit einem Exit-Code ungleich null, wenn Fehler vorliegen
(z. B. eine fehlende `reason`), und eignet sich daher als Pre-Commit-Hook oder
CI-Gate für die Waiver-Datei selbst.

## Flags

| Flag | Beschreibung | Standard |
| --- | --- | --- |
| `--waivers` | Pfad zur Waiver-Datei | automatische Erkennung von `.infraguard/waivers.yaml` |
| `--rules-dir` | (`lint`) Regeln unter diesem Verzeichnis ebenfalls als bekannt behandeln | — |

## Verwandte scan-Flags

Waiver werden während `infraguard scan` angewendet. Die relevanten Flags sind:

| Flag | Beschreibung | Standard |
| --- | --- | --- |
| `--waivers` | Pfad zur Waiver-Datei | automatische Erkennung |
| `--no-waivers` | Alle Waiver ignorieren (Inline-Kommentare und Datei) | `false` |
| `--show-waived` | Waived Verstöße anzeigen, anstatt sie auszublenden | `false` |
| `--fail-on-expired` | Abgelaufene Waiver als echte Verstöße behandeln | `true` |

Siehe [infraguard scan](./scan) und den [Waiver-Leitfaden](../user-guide/waivers).
