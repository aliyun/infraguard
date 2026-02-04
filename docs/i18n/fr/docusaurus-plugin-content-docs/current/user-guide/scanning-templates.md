---
title: Scanner les Modèles
---

# Scanner les Modèles

La commande `infraguard scan` évalue vos modèles ROS par rapport aux politiques de conformité.

## Utilisation de Base

```bash
infraguard scan <template> -p <policy>
```

### Arguments Requis

- `<template>`: Chemin vers votre fichier de modèle ROS (YAML ou JSON) - argument positionnel

### Flags Requis

- `-p, --policy <id>`: Politique à appliquer (peut être utilisée plusieurs fois)

### Flags Optionnels

- `--format <format>`: Format de sortie (`table`, `json`, ou `html`)
- `-o, --output <file>`: Chemin du fichier de sortie (pour les formats HTML et JSON)
- `--lang <lang>`: Langue de sortie (`en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`)
- `-m, --mode <mode>`: Mode de scan : `static` pour analyse locale ou `preview` pour ROS PreviewStack API (par défaut : `static`)
- `-i, --input <value>`: Valeurs de paramètres au format `key=value`, JSON, ou chemin de fichier (peut être spécifié plusieurs fois)

## Types de Politiques

Vous pouvez scanner avec différents types de politiques :

### 1. Règles Individuelles

Scanner avec une règle de conformité spécifique :

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip
```

### 2. Packs de Conformité

Scanner avec un pack de conformité prédéfini :

```bash
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

### 3. Correspondance de Motifs Génériques

Utilisez des motifs génériques (`*`) pour correspondre à plusieurs règles ou packs :

**Correspondre à toutes les règles :**
```bash
infraguard scan template.yaml -p "rule:*"
```

**Correspondre les règles par préfixe :**
```bash
infraguard scan template.yaml -p "rule:aliyun:ecs-*"
```

### 4. Fichiers de Politiques Personnalisées

Scanner avec votre propre fichier de politique Rego :

```bash
infraguard scan template.yaml -p ./my-custom-rule.rego
```

### 5. Répertoires de Politiques

Scanner avec toutes les politiques dans un répertoire :

```bash
infraguard scan template.yaml -p ./my-policies/
```

## Modes de Scan

InfraGuard supporte deux modes de scan :

### Mode Statique (Par Défaut)

Effectue une analyse statique locale du modèle sans nécessiter d'accès au fournisseur de cloud :

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode static
```

Ce mode analyse la structure du modèle et les configurations de ressources localement. Il est rapide et ne nécessite pas de identifiants cloud, mais peut ne pas supporter toutes les fonctionnalités ROS (voir [Support des Fonctionnalités ROS](./ros-features)).

### Mode Preview

Utilise l'API ROS PreviewStack pour valider les modèles avec une évaluation réelle du fournisseur de cloud :

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --mode preview
```

Le mode preview fournit une analyse plus précise pour les fonctionnalités qui nécessitent une évaluation à l'exécution (telles que `Fn::GetAtt`, `Fn::GetAZs`, etc.). Ce mode nécessite que les identifiants ROS soient configurés.

Pour les modèles utilisant des fonctionnalités non supportées par l'analyse statique, nous recommandons d'utiliser `--mode preview` pour des résultats plus précis.

## Plusieurs Politiques

Appliquer plusieurs politiques dans un seul scan :

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

## Formats de Sortie

### Format Tableau (Par Défaut)

Affiche les résultats dans un tableau codé par couleur :

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

Exemple de sortie :

```
┌──────────────────────┬────────────┬──────────────┬──────────────────────┬─────────────────────────┐
│ RULE ID              │ SEVERITY   │ RESOURCE     │ REASON               │ RECOMMENDATION          │
├──────────────────────┼────────────┼──────────────┼──────────────────────┼─────────────────────────┤
│ ecs-no-public-ip     │ high       │ MyECS        │ Public IP allocated  │ Use NAT Gateway instead │
└──────────────────────┴────────────┴──────────────┴──────────────────────┴─────────────────────────┘
```

### Format JSON

Format lisible par machine pour l'intégration CI/CD :

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

Sortie :

```json
{
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "violations": [
    {
      "rule_id": "ecs-no-public-ip",
      "severity": "high",
      "resource_id": "MyECS",
      "reason": "Public IP allocated",
      "recommendation": "Use NAT Gateway instead"
    }
  ]
}
```

### Rapport HTML

Rapport HTML interactif avec filtrage et recherche :

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Ouvrez `report.html` dans votre navigateur pour une expérience interactive.

## Codes de Sortie

InfraGuard utilise différents codes de sortie pour indiquer les résultats du scan :

- `0`: Aucune violation trouvée
- `1`: Violations trouvées
- `2`: Violations de haute sévérité trouvées

Cela est utile pour les pipelines CI/CD :

```bash
#!/bin/bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
if [ $? -eq 2 ]; then
  echo "Violations de haute sévérité trouvées ! Blocage du déploiement."
  exit 1
fi
```

## Exemples

### Exemple 1 : Audit de Sécurité

```bash
infraguard scan production.yaml \
  -p pack:aliyun:security-group-best-practice \
  -p pack:aliyun:resource-protection-best-practice \
  --format html \
  -o security-audit.html
```

### Exemple 2 : Vérification de Conformité

```bash
infraguard scan template.yaml \
  -p pack:aliyun:mlps-level-3-pre-check-compliance-pack \
  -p pack:aliyun:iso-27001-compliance \
  --lang fr \
  --format json \
  -o compliance-report.json
```

### Exemple 3 : Intégration CI/CD

```bash
# Dans votre pipeline CI/CD
infraguard scan "${TEMPLATE_FILE}" \
  -p pack:aliyun:quick-start-compliance-pack \
  --format json \
  --lang en
```

### Exemple 4 : Mode Preview avec Paramètres

Scanner en utilisant le mode preview avec paramètres de modèle :

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input InstanceType=ecs.c6.large \
  --input ImageId=centos_7_9_x64_20G_alibase_20231219.vhd
```

Vous pouvez également fournir des paramètres depuis un fichier JSON :

```bash
infraguard scan template.yaml \
  -p pack:aliyun:quick-start-compliance-pack \
  --mode preview \
  --input parameters.json
```

## Conseils

1. **Commencer avec le Pack de Démarrage Rapide** : Utilisez `pack:aliyun:quick-start-compliance-pack` pour les vérifications essentielles
2. **Utiliser Plusieurs Packs** : Combinez plusieurs packs pour une couverture complète
3. **Enregistrer les Rapports** : Utilisez le format HTML pour les rapports aux parties prenantes, JSON pour l'automatisation
4. **Définir la Langue Une Fois** : Utilisez `infraguard config set lang fr` pour éviter de répéter le flag `--lang`

## Prochaines Étapes

- Apprenez-en plus sur [Gestion des Politiques](./managing-policies)
- Explorez [Formats de Sortie](./output-formats) en détail
- Configurez [Configuration](./configuration)
