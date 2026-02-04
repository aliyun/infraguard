---
title: Support des Fonctionnalités ROS
---

# Support des Fonctionnalités ROS

InfraGuard supporte une large gamme de fonctionnalités de modèles ROS (Resource Orchestration Service) pour l'analyse statique et la validation de votre code d'infrastructure.

## Fonctions

InfraGuard supporte les fonctions ROS suivantes :

### Fonctions de Chaîne
- [`Fn::Join`](https://www.alibabacloud.com/help/en/ros/user-guide/function-join) - Joint des chaînes avec un délimiteur
- [`Fn::Sub`](https://www.alibabacloud.com/help/en/ros/user-guide/function-sub) - Substitue des variables dans une chaîne
- [`Fn::Split`](https://www.alibabacloud.com/help/en/ros/user-guide/function-split) - Divise une chaîne en liste
- [`Fn::Replace`](https://www.alibabacloud.com/help/en/ros/user-guide/function-replace) - Remplace des chaînes dans le texte
- [`Fn::Str`](https://www.alibabacloud.com/help/en/ros/user-guide/function-str) - Convertit des valeurs en chaînes
- [`Fn::Indent`](https://www.alibabacloud.com/help/en/ros/user-guide/function-indent) - Indente le texte

### Fonctions d'Encodage
- [`Fn::Base64Encode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64encode) - Encode en Base64
- [`Fn::Base64Decode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64decode) - Décode depuis Base64

### Fonctions de Liste
- [`Fn::Select`](https://www.alibabacloud.com/help/en/ros/user-guide/function-select) - Sélectionne un élément d'une liste
- [`Fn::Index`](https://www.alibabacloud.com/help/en/ros/user-guide/function-index) - Trouve l'index d'un élément
- [`Fn::Length`](https://www.alibabacloud.com/help/en/ros/user-guide/function-length) - Retourne la longueur d'une liste ou chaîne
- [`Fn::ListMerge`](https://www.alibabacloud.com/help/en/ros/user-guide/function-listmerge) - Fusionne plusieurs listes

### Fonctions de Carte
- [`Fn::FindInMap`](https://www.alibabacloud.com/help/en/ros/user-guide/function-findinmap) - Récupère des valeurs d'un mappage
- [`Fn::SelectMapList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-selectmaplist) - Sélectionne des valeurs d'une liste de cartes
- [`Fn::MergeMapToList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-mergemaptolist) - Fusionne des cartes en liste

### Fonctions Mathématiques
- [`Fn::Add`](https://www.alibabacloud.com/help/en/ros/user-guide/function-add) - Additionne des nombres
- [`Fn::Avg`](https://www.alibabacloud.com/help/en/ros/user-guide/function-avg) - Calcule la moyenne
- [`Fn::Max`](https://www.alibabacloud.com/help/en/ros/user-guide/function-max) - Retourne la valeur maximale
- [`Fn::Min`](https://www.alibabacloud.com/help/en/ros/user-guide/function-min) - Retourne la valeur minimale
- [`Fn::Calculate`](https://www.alibabacloud.com/help/en/ros/user-guide/function-calculate) - Évalue des expressions mathématiques

### Fonctions Conditionnelles
- [`Fn::If`](https://www.alibabacloud.com/help/en/ros/user-guide/function-if) - Retourne des valeurs basées sur des conditions
- [`Fn::Equals`](https://www.alibabacloud.com/help/en/ros/user-guide/function-equals) - Compare deux valeurs
- [`Fn::And`](https://www.alibabacloud.com/help/en/ros/user-guide/function-and) - ET logique
- [`Fn::Or`](https://www.alibabacloud.com/help/en/ros/user-guide/function-or) - OU logique
- [`Fn::Not`](https://www.alibabacloud.com/help/en/ros/user-guide/function-not) - NON logique
- [`Fn::Contains`](https://www.alibabacloud.com/help/en/ros/user-guide/function-contains) - Vérifie si une valeur est dans une liste
- [`Fn::Any`](https://www.alibabacloud.com/help/en/ros/user-guide/function-any) - Vérifie si une condition est vraie
- [`Fn::EachMemberIn`](https://www.alibabacloud.com/help/en/ros/user-guide/function-eachmemberin) - Vérifie si tous les éléments sont dans une autre liste
- [`Fn::MatchPattern`](https://www.alibabacloud.com/help/en/ros/user-guide/function-matchpattern) - Correspond à un motif

### Fonctions Utilitaires
- [`Fn::GetJsonValue`](https://www.alibabacloud.com/help/en/ros/user-guide/function-getjsonvalue) - Extrait des valeurs de JSON
- [`Ref`](https://www.alibabacloud.com/help/en/ros/user-guide/ref) - Référence des paramètres et ressources

## Conditions

InfraGuard supporte entièrement la fonctionnalité [Conditions ROS](https://www.alibabacloud.com/help/ros/user-guide/conditions), incluant :

- **Définition de Condition** - Définir des conditions dans la section `Conditions`
- **Fonctions de Condition** - Utiliser `Fn::Equals`, `Fn::And`, `Fn::Or`, `Fn::Not`, `Fn::If` dans les conditions
- **Références de Condition** - Référencer des conditions dans les ressources et sorties
- **Résolution de Dépendances** - Résout automatiquement les dépendances de conditions

## Syntaxe YAML Courte

InfraGuard supporte la syntaxe YAML courte (notation de tag) pour les fonctions ROS :

- `!Ref` - Forme courte de `Ref`
- `!GetAtt` - Forme courte de `Fn::GetAtt`
- Toutes les autres fonctions `Fn::*` peuvent être écrites comme `!FunctionName`

L'analyseur YAML convertit automatiquement ces formes courtes en leur représentation de carte standard lors du chargement du modèle.

## Fonctionnalités Non Supportées

InfraGuard se concentre sur l'analyse statique et ne supporte actuellement pas les fonctionnalités suivantes en mode statique :

### Fonctions d'Exécution
- `Fn::GetAtt` - Nécessite la création réelle de ressources pour récupérer les attributs
- `Fn::GetAZs` - Nécessite une requête d'exécution au fournisseur de cloud
- `Fn::GetStackOutput` - Nécessite l'accès aux sorties d'autres piles

### Sections de Modèle
- `Locals` - Définitions de variables locales
- `Transform` - Transformations et macros de modèle
- `Rules` - Règles de validation de modèle
- `Mappings` - Mappages de valeurs statiques (non analysés pour violations de politiques)

### Références Spéciales
- Paramètres pseudo (p. ex., `ALIYUN::StackId`, `ALIYUN::Region`, etc.) - Paramètres fournis par le système

Ces fonctionnalités seront préservées telles quelles dans la sortie d'analyse sans évaluation ou validation lors de l'utilisation du mode statique.

> **Astuce** : Pour les modèles utilisant des fonctionnalités non supportées par l'analyse statique (telles que `Fn::GetAtt`, `Fn::GetAZs`, etc.), nous recommandons d'utiliser `--mode preview` pour tirer parti de l'API ROS PreviewStack pour une analyse plus précise. Le mode preview évalue les modèles avec le contexte réel du fournisseur de cloud, permettant le support des fonctions d'exécution et d'autres fonctionnalités dynamiques.

## Ressources Connexes

- [Structure de Modèle ROS](https://www.alibabacloud.com/help/en/ros/user-guide/template-structure)
- [Fonctions ROS](https://www.alibabacloud.com/help/en/ros/user-guide/functions)
- [Conditions ROS](https://www.alibabacloud.com/help/en/ros/user-guide/conditions)
