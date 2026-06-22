---
title: Exenciones
---

# Exenciones (Supresiones)

Cuando una violación es conocida y aceptada — un recurso heredado, un riesgo
mitigado en otro lugar, una excepción temporal — puede **eximirla** en lugar de
deshabilitar la regla por completo o eludir InfraGuard. Una exención es una
decisión explícita y auditable: siempre lleva un motivo y, idealmente, una fecha
de caducidad.

InfraGuard nunca descarta silenciosamente un hallazgo exento. Las exenciones
activas se ocultan de la salida predeterminada pero se contabilizan en el resumen;
las exenciones caducadas reaparecen como violaciones reales para que se renueven.

## Dos formas de eximir

### 1. Comentarios en línea

Anote el recurso directamente en la plantilla. Funciona tanto para ROS (YAML) como
para Terraform (HCL):

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

Sintaxis:

```
infraguard:ignore=<rule-id>[,<rule-id>...] reason="..." [expires=YYYY-MM-DD]
infraguard:ignore=*  reason="..."     # suprimir todas las reglas en este recurso
```

Una directiva colocada sobre o justo encima de un recurso se aplica a ese recurso.
Una directiva sin un `reason` se ignora.

### 2. Archivo central de exenciones

Para exenciones por lotes o gobernadas, confirme un `.infraguard/waivers.yaml` en
su repositorio (pasa por la revisión de código como cualquier otro cambio):

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

| Campo | Significado | Requerido |
| --- | --- | --- |
| `rule` | ID corto de la regla, o `*` para todas las reglas | Sí |
| `resource` | ID del recurso, exacto o glob | No (cualquier recurso) |
| `files` | Globs de rutas de archivo (`*`, `**`) | No (cualquier archivo) |
| `reason` | Justificación | Sí |
| `expires` | `YYYY-MM-DD`; vacío significa permanente | No (recomendado) |
| `owner` | Persona responsable | No (recomendado) |

Las directivas en línea tienen prioridad sobre las exenciones del archivo para el
mismo recurso.

## Comportamiento durante un escaneo

- Exención **activa** → la violación se oculta y se contabiliza como `waived` en el resumen.
- Exención **caducada** → la violación se muestra de nuevo y, de forma predeterminada, hace fallar la compilación.
- **Sin exención** → una violación normal.

```bash
infraguard scan -p pack:aliyun:... template.yaml          # waivers applied automatically
infraguard scan ... --show-waived template.yaml           # show what was waived
infraguard scan ... --no-waivers template.yaml            # full view, ignore all waivers
infraguard scan ... --fail-on-expired=false template.yaml # don't fail on expired waivers
```

Para CI, un equipo de seguridad puede ejecutar `--no-waivers` para ver el panorama
completo, o mantener las exenciones pero confiar en el `--fail-on-expired`
predeterminado para forzar las renovaciones.

## Gobernar las exenciones

```bash
infraguard waiver list    # show every waiver and its status
infraguard waiver lint    # find missing reasons, unknown rules, expired entries
```

Añada `waiver lint` al pre-commit o CI para que el propio archivo de exenciones se
mantenga en buen estado. Consulte la [referencia de CLI de waiver](../cli/waiver).

## Una nota sobre la seguridad

Las exenciones ocultan riesgo de forma legítima, por lo que están restringidas a
propósito: un `reason` es obligatorio, las exenciones caducadas fallan de forma
predeterminada, la salida JSON siempre conserva los elementos exentos para
auditoría, y el archivo se revisa a través de Git. Prefiera exenciones estrechas
(regla + recurso + archivo) sobre las amplias, y siempre establezca una fecha de
`expires`.
