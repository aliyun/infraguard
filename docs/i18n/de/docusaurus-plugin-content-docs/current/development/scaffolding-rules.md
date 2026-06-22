---
title: Regeln Gerüsten & Testen
---

# Benutzerdefinierte Regeln Gerüsten & Testen

InfraGuard liefert über 600 integrierte Regeln, aber die meisten Teams haben auch
private Compliance-Anforderungen (Namenskonventionen, obligatorische Kosten-Tags,
interne CIDR-Regeln …). Diese Seite zeigt den schnellen Weg, eigene Regeln zu
erstellen und zu verifizieren, ohne die CLI zu verlassen.

Der Ablauf ist: **`policy new` → bearbeiten → `policy test` → `scan`**.

## 1. Eine Regel gerüsten

```bash
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance \
  --name-en "ECS instance must have owner tag" \
  --name-zh "ECS 实例必须包含 owner 标签"
```

Dies generiert ein bearbeitungsbereites Gerüst unter `./policies` (mit `--dir`
überschreibbar):

```
policies/
├── rules/
│   ├── ros/ecs-instance-must-have-owner-tag.rego
│   └── terraform/ecs-instance-must-have-owner-tag.rego
└── testdata/aliyun/rules/ecs-instance-must-have-owner-tag/
    ├── ros/{compliant.yaml, violation.yaml}
    └── terraform/{compliant/main.tf, violation/main.tf}
```

Die generierte `.rego` füllt den `rule_meta`-Block (id, severity,
Namensplatzhalter in 7 Sprachen, Ressourcentypen) und eine minimale `deny`-Regel
mit `TODO`-Markierungen vor. Benutzerdefinierte Regeln können die integrierten
Helfer frei importieren (`data.infraguard.helpers`,
`data.infraguard.helpers.terraform`) — InfraGuard injiziert sie automatisch beim
Scannen oder Testen. Siehe [Hilfsfunktionen](./helper-functions) und
[Regeln Schreiben](./writing-rules).

## 2. Die Logik implementieren

Bearbeiten Sie die generierten Dateien und ersetzen Sie die `TODO`-Markierungen.
Zum Beispiel die ROS-Regel:

```rego
is_compliant(resource) if {
	helpers.has_tags(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Tags"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
```

Machen Sie dann die Fixtures aussagekräftig: Das `compliant`-Fixture sollte die
Regel erfüllen (z. B. das `owner`-Tag enthalten) und das `violation`-Fixture sollte
sie verletzen.

## Regeln Testen

`infraguard policy test` wertet jede Regel anhand ihrer Fixtures aus und verwendet
dabei dieselbe Engine wie `scan`:

- `compliant`-Fixtures dürfen **keine** Verstöße gegen die Regel erzeugen.
- `violation`-Fixtures müssen **mindestens einen** erzeugen.

```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule ecs-instance-must-have-owner-tag
infraguard policy test --dir ./policies --iac terraform
infraguard policy test --dir ./policies --format json   # maschinenlesbar, für CI
```

Beispielausgabe:

```
RULE                              CASE                  STATUS
ecs-instance-must-have-owner-tag  ros/compliant         ✓ pass
ecs-instance-must-have-owner-tag  ros/violation         ✓ pass
ecs-instance-must-have-owner-tag  terraform/compliant   ✓ pass
ecs-instance-must-have-owner-tag  terraform/violation   ✓ pass

1 rules, 4 cases: 4 passed, 0 failed
```

Exit-Codes: `0` alle bestanden, `1` ein Fall fehlgeschlagen, `2` keine Fixtures
gefunden (mit `--allow-empty` überschreibbar). Dadurch wird `policy test` zu einem
natürlichen CI-Gate für ein Repository mit benutzerdefinierten Regeln.

## 3. Die Regel in einem Scan verwenden

Richten Sie `scan` auf Ihr Richtlinienverzeichnis:

```bash
infraguard scan -p ./policies my-template.yaml
```

## Tipps

- Verwenden Sie `infraguard policy validate ./policies` für statische Prüfungen
  (Syntax, Vollständigkeit von `rule_meta`), bevor `policy test` die
  Verhaltenstests ausführt.
- Halten Sie die ROS- und Terraform-Implementierungen derselben Regel unter
  derselben ID; sie teilen sich die Metadaten der Regel und werden automatisch
  zusammengeführt.
- Die vollständige Flag-Liste finden Sie in der [policy-CLI-Referenz](../cli/policy).
