---
title: Questions Fréquemment Posées
---

# Questions Fréquemment Posées

## Général

### Qu'est-ce qu'InfraGuard ?

InfraGuard est un outil en ligne de commande qui valide les modèles Infrastructure as Code (IaC) par rapport aux politiques de conformité avant le déploiement. Il aide à détecter les problèmes de sécurité et de conformité tôt dans le cycle de développement.

### Quels fournisseurs de cloud sont supportés ?

Actuellement, InfraGuard supporte les modèles Alibaba Cloud (Aliyun) ROS. Le support pour d'autres fournisseurs peut être ajouté dans les versions futures.

### InfraGuard est-il gratuit ?

Oui, InfraGuard est open source et publié sous la Licence Apache 2.0.

## Utilisation

### Comment scanner un modèle ?

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

Voir le [Guide de Démarrage Rapide](./getting-started/quick-start) pour plus d'exemples.

### Puis-je utiliser plusieurs politiques dans un scan ?

Oui ! Utilisez plusieurs flags `-p` :

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip -p pack:aliyun:quick-start-compliance-pack
```

### Quels formats de sortie sont disponibles ?

InfraGuard supporte trois formats :
- **Tableau** : Sortie console colorée (par défaut)
- **JSON** : Lisible par machine pour CI/CD
- **HTML** : Rapport interactif

### Comment changer la langue ?

Utilisez le flag `--lang` ou configurez-le de manière permanente :

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang fr
# Ou configurer de manière permanente
infraguard config set lang fr
```

InfraGuard supporte 7 langues :
- `en` - English (Anglais)
- `zh` - Chinese (中文)
- `es` - Spanish (Espagnol)
- `fr` - French (Français)
- `de` - German (Allemand)
- `ja` - Japanese (日本語)
- `pt` - Portuguese (Portugais)

## Politiques

### Où sont stockées les politiques ?

Les politiques sont intégrées dans le binaire. Vous pouvez également stocker des politiques personnalisées dans `~/.infraguard/policies/`.

### Comment mettre à jour les politiques ?

```bash
infraguard policy update
```

### Puis-je écrire des politiques personnalisées ?

Oui ! Les politiques sont écrites en Rego (langage Open Policy Agent). Voir le [Guide de Développement](./development/writing-rules).

### Comment valider ma politique personnalisée ?

```bash
infraguard policy validate my-rule.rego
```
