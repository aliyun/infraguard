---
title: Bienvenue dans InfraGuard
sidebar_label: Introduction
---

# InfraGuard

**Politique Définie. Infrastructure Sécurisée.**

**CLI de pré-vérification de conformité Infrastructure as Code (IaC)** pour les modèles Alibaba Cloud ROS.

Évaluez vos modèles ROS YAML/JSON par rapport aux politiques de sécurité et de conformité **avant le déploiement**.

## Qu'est-ce qu'InfraGuard ?

InfraGuard est un outil en ligne de commande qui vous aide à garantir que votre code d'infrastructure respecte les normes de sécurité et de conformité avant de déployer en production. Il utilise Open Policy Agent (OPA) et les politiques Rego pour évaluer vos modèles.

## Politique comme Code

InfraGuard adopte l'approche **Policy as Code** - traiter les politiques de conformité comme des artefacts de code de première classe qui peuvent être versionnés, testés et automatisés.

- **Contrôle de Version** - Stockez les politiques dans Git aux côtés de votre code d'infrastructure. Suivez les changements, examinez l'historique et restaurez si nécessaire.
- **Tests Automatisés** - Écrivez des tests unitaires pour vos politiques en utilisant des modèles d'exemple. Assurez-vous que les politiques fonctionnent correctement avant de les appliquer en production.
- **Revue de Code** - Appliquez le même processus de revue par les pairs aux changements de politiques que pour le code d'application. Détectez les problèmes tôt grâce à la collaboration.
- **Intégration CI/CD** - Intégrez les vérifications de politiques dans votre pipeline CI/CD. Validez automatiquement chaque changement d'infrastructure par rapport aux exigences de conformité.
- **Réutilisabilité** - Composez des règles individuelles en packs de conformité. Partagez les politiques entre les équipes et les projets pour maintenir la cohérence.
- **Déclaratif** - Définissez *ce que* signifie la conformité en utilisant la syntaxe déclarative de Rego, pas *comment* la vérifier. Concentrez-vous sur le résultat, pas sur l'implémentation.

## Caractéristiques Clés

- **Validation Pré-déploiement** - Détectez les problèmes de conformité avant qu'ils n'atteignent la production
- **Packs de Politiques** - Packs de conformité préconstruits (MLPS, ISO 27001, PCI-DSS, etc.)
- **Internationalisation** - Support complet pour 7 langues (Anglais, Chinois, Espagnol, Français, Allemand, Japonais, Portugais)
- **Plusieurs Formats de Sortie** - Tableaux, JSON et rapports HTML
- **Extensible** - Écrivez des politiques personnalisées en Rego
- **Rapide** - Construit en Go pour la vitesse et l'efficacité

## Fournisseurs Supportés

- **Aliyun (Alibaba Cloud)** - Des centaines de règles et des dizaines de packs de conformité

## Exemple Rapide

```bash
# Scanner un modèle avec un pack de conformité
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Scanner avec des règles spécifiques
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Générer un rapport HTML
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## Commencer

Prêt à améliorer la conformité de votre infrastructure ? Consultez notre [Guide de Démarrage Rapide](./getting-started/quick-start) pour commencer.

## Bibliothèque de Politiques

Parcourez notre [Référence des Politiques](./policies/aliyun/rules) complète pour voir toutes les règles et packs de conformité disponibles.
