---
title: Génération et Test des Règles
---

# Génération et Test de Règles Personnalisées

InfraGuard est livré avec plus de 600 règles intégrées, mais la plupart des équipes ont également des exigences
de conformité privées (conventions de nommage, tags de coût obligatoires, règles CIDR internes…).
Cette page présente la voie rapide pour rédiger et vérifier vos propres règles sans quitter
la CLI.

La boucle est : **`policy new` → édition → `policy test` → `scan`**.

## 1. Générer une règle

```bash
infraguard policy new ecs-instance-must-have-owner-tag \
  --iac both --severity medium \
  --resource-type ALIYUN::ECS::Instance \
  --tf-resource-type alicloud_instance \
  --name-en "ECS instance must have owner tag" \
  --name-zh "ECS 实例必须包含 owner 标签"
```

Cela génère un squelette prêt à éditer sous `./policies` (remplacé par `--dir`) :

```
policies/
├── rules/
│   ├── ros/ecs-instance-must-have-owner-tag.rego
│   └── terraform/ecs-instance-must-have-owner-tag.rego
└── testdata/aliyun/rules/ecs-instance-must-have-owner-tag/
    ├── ros/{compliant.yaml, violation.yaml}
    └── terraform/{compliant/main.tf, violation/main.tf}
```

Le `.rego` généré pré-remplit le bloc `rule_meta` (id, sévérité, espaces réservés de noms en
7 langues, types de ressources) et une règle `deny` minimale avec des marqueurs `TODO`.
Les règles personnalisées peuvent importer librement les helpers intégrés (`data.infraguard.helpers`,
`data.infraguard.helpers.terraform`) — InfraGuard les injecte automatiquement lorsque
vous scannez ou testez. Consultez [Fonctions Helper](./helper-functions) et
[Écrire des Règles](./writing-rules).

## 2. Implémenter la logique

Éditez les fichiers générés et remplacez les marqueurs `TODO`. Par exemple, la règle ROS :

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

Ensuite, rendez les fixtures significatives : la fixture `compliant` doit satisfaire la règle
(par exemple inclure le tag `owner`) et la fixture `violation` doit l'enfreindre.

## Tester les Règles

`infraguard policy test` évalue chaque règle par rapport à ses fixtures en utilisant le même
moteur que `scan` :

- Les fixtures `compliant` ne doivent produire **aucune** violation de la règle.
- Les fixtures `violation` doivent en produire **au moins une**.

```bash
infraguard policy test --dir ./policies
infraguard policy test --dir ./policies --rule ecs-instance-must-have-owner-tag
infraguard policy test --dir ./policies --iac terraform
infraguard policy test --dir ./policies --format json   # machine-readable, for CI
```

Exemple de sortie :

```
RULE                              CASE                  STATUS
ecs-instance-must-have-owner-tag  ros/compliant         ✓ pass
ecs-instance-must-have-owner-tag  ros/violation         ✓ pass
ecs-instance-must-have-owner-tag  terraform/compliant   ✓ pass
ecs-instance-must-have-owner-tag  terraform/violation   ✓ pass

1 rules, 4 cases: 4 passed, 0 failed
```

Codes de sortie : `0` tout passe, `1` un cas a échoué, `2` aucune fixture trouvée (remplacer avec
`--allow-empty`). Cela fait de `policy test` un contrôle CI naturel pour un dépôt de règles personnalisées.

## 3. Utiliser la règle dans un scan

Pointez `scan` vers votre répertoire de politiques :

```bash
infraguard scan -p ./policies my-template.yaml
```

## Astuces

- Utilisez `infraguard policy validate ./policies` pour les vérifications statiques (syntaxe,
  complétude de `rule_meta`) avant que `policy test` n'exécute les tests de comportement.
- Conservez les implémentations ROS et Terraform de la même règle sous le même ID ;
  elles partagent les métadonnées de la règle et sont fusionnées automatiquement.
- Consultez la [référence CLI policy](../cli/policy) pour la liste complète des flags.
