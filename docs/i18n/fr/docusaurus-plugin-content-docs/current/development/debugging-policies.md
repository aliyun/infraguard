---
title: Débogage de Politiques
---

# Débogage de Politiques Rego

Il existe deux façons de déboguer vos politiques Rego : utiliser des instructions print ou utiliser le débogueur VSCode.

## Méthode 1 : Utiliser des Instructions Print

### Utilisation de Base

Ajoutez des instructions `print()` n'importe où dans votre politique Rego :

```rego
package infraguard.rules.aliyun.my_rule

import rego.v1
import data.infraguard.helpers

deny contains result if {
    print("Starting policy evaluation")
    
    some name, resource in helpers.resources_by_types(rule_meta.resource_types)
    print("Checking resource:", name)
    print("Resource type:", resource.Type)
    
    not is_compliant(resource)
    print("Found violation for resource:", name)
    
    result := {...}
}
```

### Format de Sortie

Les instructions print envoient la sortie vers stderr avec l'emplacement du fichier :

```
/path/to/policy.rego:42: Starting policy evaluation
/path/to/policy.rego:45: Checking resource: MyBucket
/path/to/policy.rego:46: Resource type: ALIYUN::OSS::Bucket
/path/to/policy.rego:49: Found violation for resource: MyBucket
```

### Exemples d'Utilisation Courants

**Inspecter les Données d'Entrée :**
```rego
print("Input keys:", object.keys(input))
print("Template version:", input.ROSTemplateFormatVersion)
print("Number of resources:", count(input.Resources))
```

**Déboguer l'Itération de Ressources :**
```rego
some name, resource in helpers.resources_by_types(rule_meta.resource_types)
print("Resource:", name)
print("Properties:", object.keys(resource.Properties))
```

**Vérifier les Conditions :**
```rego
condition1 := some_check(resource)
print("Condition 1 result:", condition1)
```

**Inspecter les Variables :**
```rego
property := helpers.get_property(resource, "SomeProperty", null)
print("Property value:", property)
print("Property type:", type_name(property))
```

## Méthode 2 : Utiliser le Débogueur VSCode

VSCode fournit une expérience de débogage plus puissante avec des points d'arrêt, l'inspection de variables et l'exécution pas à pas.

### Prérequis

1. **Installer OPA**

   Téléchargez et installez OPA depuis le site web officiel :
   
   https://www.openpolicyagent.org/docs#1-download-opa

2. **Installer Regal**

   Installez Regal pour un développement Rego amélioré :
   
   https://www.openpolicyagent.org/projects/regal#download-regal

3. **Installer l'Extension OPA VSCode**

   Installez l'extension OPA officielle depuis le marketplace VSCode :
   
   https://marketplace.visualstudio.com/items?itemName=tsandall.opa

### Étapes de Configuration

1. **Préparer l'Entrée de Test**

   Créez un fichier nommé `input.json` dans votre répertoire de politiques avec vos données de test :

   ```json
   {
     "ROSTemplateFormatVersion": "2015-09-01",
     "Resources": {
       "MyBucket": {
         "Type": "ALIYUN::OSS::Bucket",
         "Properties": {
           "BucketName": "test-bucket",
           "AccessControl": "private"
         }
       }
     }
   }
   ```

2. **Définir des Points d'Arrêt**

   Ouvrez votre fichier de politique `.rego` dans VSCode et cliquez sur la marge gauche pour définir des points d'arrêt où vous voulez mettre en pause l'exécution.

3. **Démarrer le Débogage**

   - Appuyez sur `F5` ou allez dans Exécuter → Démarrer le Débogage
   - Le débogueur s'arrêtera à vos points d'arrêt
   - Vous pouvez inspecter les variables, exécuter pas à pas et évaluer des expressions

## Choisir une Méthode

- **Instructions Print** : Rapides et simples, fonctionnent dans n'importe quel environnement, utiles pour le débogage en production
- **Débogueur VSCode** : Plus puissant, débogage interactif avec inspection complète des variables, meilleur pour le développement

Vous pouvez utiliser les deux méthodes ensemble : utilisez les instructions print pour des vérifications rapides et le débogueur pour une investigation approfondie.
