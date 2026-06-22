---
title: Dérogations
---

# Dérogations (Suppressions)

Lorsqu'une violation est connue et acceptée — une ressource héritée, un risque atténué
ailleurs, une exception temporaire — vous pouvez la **déroger** au lieu de désactiver la
règle entièrement ou de contourner InfraGuard. Une dérogation est une décision explicite et auditable :
elle porte toujours une raison et, idéalement, une date d'expiration.

InfraGuard ne supprime jamais silencieusement une constatation dérogée. Les dérogations actives sont masquées
de la sortie par défaut mais comptabilisées dans le résumé ; les dérogations expirées réapparaissent comme de vraies
violations afin d'être renouvelées.

## Deux façons de déroger

### 1. Commentaires en ligne

Annotez la ressource directement dans le modèle. Fonctionne pour ROS (YAML) et
Terraform (HCL) :

```yaml
Resources:
  # infraguard:ignore=oss-bucket-public-read-prohibited reason="legacy bucket, migrating 2026Q4" expires=2026-12-31
  LegacyBucket:
    Type: ALIYUN::OSS::Bucket
    Properties:
      AccessControl: public-read
```

```hcl
resource "alicloud_oss_bucket" "legacy" {
  # infraguard:ignore=oss-bucket-public-read-prohibited reason="legacy bucket" expires=2026-12-31
  bucket = "legacy"
  acl    = "public-read"
}
```

Syntaxe :

```
infraguard:ignore=<rule-id>[,<rule-id>...] reason="..." [expires=YYYY-MM-DD]
infraguard:ignore=*  reason="..."     # supprime toutes les règles sur cette ressource
```

Une directive placée sur ou juste au-dessus d'une ressource s'applique à cette ressource. Une
directive sans `reason` est ignorée.

### 2. Fichier de dérogations central

Pour des dérogations groupées ou gouvernées, validez un `.infraguard/waivers.yaml` dans votre dépôt
(il passe par la revue de code comme tout autre changement) :

```yaml
version: 1
waivers:
  - rule: oss-bucket-public-read-prohibited
    resource: "LegacyBucket"          # exact ID or glob, e.g. "legacy-*"
    files: ["envs/legacy/**"]          # optional file globs (supports **)
    reason: "Legacy resource, approved in CAB-1234"
    expires: 2026-09-30
    owner: alice@example.com

  - rule: rds-instance-enabled-tde
    resource: "*"                      # all matching resources
    files: ["sandbox/**"]
    reason: "Sandbox environment does not require TDE"
    # no expires → permanent waiver (flagged by `waiver lint`)
```

| Champ | Signification | Requis |
| --- | --- | --- |
| `rule` | ID de règle court, ou `*` pour toutes les règles | Oui |
| `resource` | ID de ressource, exact ou glob | Non (toute ressource) |
| `files` | Globs de chemins de fichiers (`*`, `**`) | Non (tout fichier) |
| `reason` | Justification | Oui |
| `expires` | `YYYY-MM-DD` ; vide signifie permanent | Non (recommandé) |
| `owner` | Personne responsable | Non (recommandé) |

Les directives en ligne ont priorité sur les dérogations de fichier pour la même ressource.

## Comportement lors d'un scan

- Dérogation **active** → la violation est masquée et comptabilisée comme `waived` dans le résumé.
- Dérogation **expirée** → la violation est affichée à nouveau et, par défaut, fait échouer la build.
- **Aucune dérogation** → une violation normale.

```bash
infraguard scan -p pack:aliyun:... template.yaml          # waivers applied automatically
infraguard scan ... --show-waived template.yaml           # show what was waived
infraguard scan ... --no-waivers template.yaml            # full view, ignore all waivers
infraguard scan ... --fail-on-expired=false template.yaml # don't fail on expired waivers
```

Pour la CI, une équipe de sécurité peut exécuter `--no-waivers` pour voir le tableau complet, ou conserver
les dérogations mais s'appuyer sur le `--fail-on-expired` par défaut pour forcer les renouvellements.

## Gouverner les dérogations

```bash
infraguard waiver list    # show every waiver and its status
infraguard waiver lint    # find missing reasons, unknown rules, expired entries
```

Ajoutez `waiver lint` au pre-commit ou à la CI afin que le fichier de dérogations lui-même reste sain.
Consultez la [référence CLI waiver](../cli/waiver).

## Une note sur la sécurité

Les dérogations masquent légitimement le risque, elles sont donc contraintes à dessein : une `reason` est
obligatoire, les dérogations expirées échouent par défaut, la sortie JSON conserve toujours les éléments
dérogés pour l'audit, et le fichier est revu via Git. Préférez des dérogations étroites
(règle + ressource + fichier) aux dérogations larges, et définissez toujours une date `expires`.
