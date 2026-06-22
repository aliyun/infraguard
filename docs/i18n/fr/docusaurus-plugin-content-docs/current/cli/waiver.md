---
title: infraguard waiver
---

# infraguard waiver

Gérer les dérogations de règles (suppressions). Les dérogations vous permettent de supprimer
sciemment des violations spécifiques avec une raison et une date d'expiration optionnelle.
Consultez le [guide des dérogations](../user-guide/waivers) pour les concepts et le format
du fichier de dérogations.

## Sous-commandes

### list

Lister toutes les dérogations et leur statut (active / expirée / permanente) :
```bash
infraguard waiver list
infraguard waiver list --waivers ./path/to/waivers.yaml
```

### lint

Valider le fichier de dérogations — signale les raisons manquantes, les règles inconnues, les dates
invalides ou expirées :
```bash
infraguard waiver lint
infraguard waiver lint --rules-dir ./policies/rules   # reconnaît aussi les règles personnalisées
```

`lint` se termine avec un code non nul en cas d'erreurs (par exemple une `reason` manquante), ce qui le rend
adapté à un hook de pre-commit ou à un contrôle CI sur le fichier de dérogations lui-même.

## Flags

| Flag | Description | Défaut |
| --- | --- | --- |
| `--waivers` | Chemin vers le fichier de dérogations | détection automatique de `.infraguard/waivers.yaml` |
| `--rules-dir` | (`lint`) Traite également les règles sous ce répertoire comme connues | — |

## Flags de scan associés

Les dérogations sont appliquées lors de `infraguard scan`. Les flags pertinents sont :

| Flag | Description | Défaut |
| --- | --- | --- |
| `--waivers` | Chemin vers le fichier de dérogations | détection automatique |
| `--no-waivers` | Ignorer toutes les dérogations (commentaires en ligne et fichier) | `false` |
| `--show-waived` | Afficher les violations dérogées au lieu de les masquer | `false` |
| `--fail-on-expired` | Traiter les dérogations expirées comme de vraies violations | `true` |

Consultez [infraguard scan](./scan) et le [guide des dérogations](../user-guide/waivers).
