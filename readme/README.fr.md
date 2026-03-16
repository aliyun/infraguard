<div align="center">
  <img src="../assets/logo.png" alt="InfraGuard Logo" width="200"/>
</div>

# InfraGuard

**Politique Définie. Infrastructure Sécurisée.**

**CLI de pré-vérification de conformité Infrastructure as Code (IaC)** pour les modèles Alibaba Cloud ROS. Évaluez vos modèles ROS YAML/JSON par rapport aux politiques de sécurité et de conformité **avant le déploiement**.

> 💡 InfraGuard adopte **Policy as Code** - traiter les politiques de conformité comme des artefacts de code versionnés, testables et réutilisables.

**Langue**: [English](../README.md) | [中文](README.zh.md) | [Español](README.es.md) | Français | [Deutsch](README.de.md) | [日本語](README.ja.md) | [Português](README.pt.md)

## ✨ Fonctionnalités

- 🔍 **Validation Pré-déploiement** - Détecter les problèmes de conformité avant qu'ils n'atteignent la production
- 🎯 **Modes de Scan Double** - Analyse statique ou validation de prévisualisation basée sur le cloud
- 📦 **Règles Intégrées** - Couverture complète pour les services Aliyun
- 🏆 **Packs de Conformité** - MLPS, ISO 27001, PCI-DSS, SOC 2 et plus
- ✏️ **Intégration Éditeur** - Extension VS Code avec auto-complétion, diagnostics en temps réel et documentation au survol pour les templates ROS
- 🌍 **Support Multilingue** - Disponible en 7 langues (Français, Anglais, Chinois, Espagnol, Allemand, Japonais, Portugais)
- 🎨 **Plusieurs Formats de Sortie** - Tableaux, JSON et rapports HTML interactifs
- 🔧 **Extensible** - Écrivez des politiques personnalisées en Rego (Open Policy Agent)
- ⚡ **Rapide** - Construit en Go pour la vitesse et l'efficacité

## 🚀 Démarrage Rapide

### Installation

```bash
go install github.com/aliyun/infraguard/cmd/infraguard@latest
```

Ou téléchargez les binaires précompilés depuis [GitHub Releases](https://github.com/aliyun/infraguard/releases).

### Utilisation de Base

```bash
# Scanner avec un pack de conformité
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack

# Scanner avec une règle spécifique
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-ip

# Scanner avec un motif générique (toutes les règles)
infraguard scan template.yaml -p "rule:*"

# Scanner avec un motif générique (toutes les règles ECS)
infraguard scan template.yaml -p "rule:aliyun:ecs-*"

# Générer un rapport HTML
infraguard scan template.yaml -p pack:aliyun:mlps-level-3-pre-check-compliance-pack --format html -o report.html
```

## 📚 Documentation

Pour une documentation détaillée, veuillez visiter notre [Site de Documentation](https://aliyun.github.io/infraguard/fr/)

- **[Premiers Pas](https://aliyun.github.io/infraguard/fr/docs/getting-started/installation)** - Guide d'installation et de démarrage rapide
- **[Guide Utilisateur](https://aliyun.github.io/infraguard/fr/docs/user-guide/scanning-templates)** - Apprenez comment scanner les modèles et gérer les politiques
- **[Référence des Politiques](https://aliyun.github.io/infraguard/fr/docs/policies/aliyun/rules)** - Parcourez toutes les règles et packs de conformité disponibles
- **[Guide de Développement](https://aliyun.github.io/infraguard/fr/docs/development/writing-rules)** - Écrivez des règles et packs personnalisés
- **[Référence CLI](https://aliyun.github.io/infraguard/fr/docs/cli/scan)** - Documentation de l'interface en ligne de commande
- **[FAQ](https://aliyun.github.io/infraguard/fr/docs/faq)** - Questions fréquemment posées
