---
title: Formats de Sortie
---

# Formats de Sortie

InfraGuard supporte trois formats de sortie : Tableau, JSON et HTML.

## Format Tableau

Format par défaut avec sortie console codée par couleur. Idéal pour une utilisation interactive.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

## Format JSON

Format lisible par machine pour l'automatisation et les pipelines CI/CD.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

## Format HTML

Rapport interactif avec capacités de filtrage et de recherche.

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Pour des exemples détaillés, consultez [Scanner les Modèles](./scanning-templates).
