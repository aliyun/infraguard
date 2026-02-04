---
title: Démarrage Rapide
---

# Démarrage Rapide

Ce guide vous aidera à démarrer avec InfraGuard en quelques minutes seulement.

## Étape 1 : Créer un Modèle ROS d'Exemple

Créez un fichier nommé `template.yaml` avec le contenu suivant :

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

## Étape 2 : Exécuter Votre Premier Scan

Scannez le modèle en utilisant une règle intégrée :

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-and-anyip
```

Vous devriez voir une sortie indiquant que l'instance ECS a une IP publique allouée, ce qui est un problème de sécurité.

## Étape 3 : Utiliser un Pack de Conformité

Au lieu de règles individuelles, vous pouvez scanner avec un pack de conformité entier :

```bash
infraguard scan template.yaml -p pack:aliyun:security-group-best-practice
```

## Étape 4 : Générer un Rapport

InfraGuard supporte plusieurs formats de sortie :

### Format Tableau (Par Défaut)

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

### Format JSON

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

### Rapport HTML

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Ouvrez `report.html` dans votre navigateur pour voir un rapport interactif.

## Étape 5 : Lister les Politiques Disponibles

Pour voir toutes les règles et packs disponibles :

```bash
# Lister toutes les politiques
infraguard policy list

# Obtenir les détails d'une règle spécifique
infraguard policy get rule:aliyun:ecs-instance-no-public-ip

# Obtenir les détails d'un pack de conformité
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

## Cas d'Usage Courants

### Scanner avec Plusieurs Politiques

Vous pouvez appliquer plusieurs politiques dans un seul scan :

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

### Définir la Préférence de Langue

InfraGuard supporte 7 langues :

```bash
# Sortie en français
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang fr

# Sortie en anglais
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang en

# Autres langues supportées : zh (Chinois), es (Espagnol), de (Allemand), ja (Japonais), pt (Portugais)
```

Vous pouvez également définir la langue de manière permanente :

```bash
infraguard config set lang fr
```

Codes de langue supportés : `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. La valeur par défaut est détectée automatiquement en fonction de votre paramètre régional système.

## Prochaines Étapes

- **En Savoir Plus** : Lisez le [Guide Utilisateur](../user-guide/scanning-templates) pour des informations détaillées
- **Explorer les Politiques** : Parcourez la [Référence des Politiques](../policies/aliyun/rules) pour voir toutes les règles et packs disponibles
- **Écrire des Politiques Personnalisées** : Consultez le [Guide de Développement](../development/writing-rules) pour créer vos propres règles

## Obtenir de l'Aide

Si vous rencontrez des problèmes :

1. Consultez la page [FAQ](../faq)
2. Examinez attentivement les messages d'erreur - ils incluent généralement des indices utiles
3. Signalez les problèmes sur [GitHub](https://github.com/aliyun/infraguard/issues)
