---
title: Isenções
---

# Isenções (Supressões)

Quando uma violação é conhecida e aceita — um recurso legado, um risco mitigado
em outro lugar, uma exceção temporária — você pode **isentá-la** em vez de desativar a
regra inteira ou contornar o InfraGuard. Uma isenção é uma decisão explícita e auditável:
ela sempre carrega um motivo e, idealmente, uma data de expiração.

O InfraGuard nunca descarta silenciosamente um achado isento. Isenções ativas são ocultadas
da saída padrão, mas contabilizadas no resumo; isenções expiradas reaparecem como violações
reais para que sejam renovadas.

## Duas formas de isentar

### 1. Comentários inline

Anote o recurso diretamente no modelo. Funciona tanto para ROS (YAML) quanto para
Terraform (HCL):

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

Sintaxe:

```
infraguard:ignore=<rule-id>[,<rule-id>...] reason="..." [expires=YYYY-MM-DD]
infraguard:ignore=*  reason="..."     # suprime todas as regras neste recurso
```

Uma diretiva colocada sobre ou logo acima de um recurso se aplica a esse recurso. Uma
diretiva sem um `reason` é ignorada.

### 2. Arquivo central de isenções

Para isenções em lote ou governadas, faça commit de um `.infraguard/waivers.yaml` no seu repositório
(ele passa por revisão de código como qualquer outra alteração):

```yaml
version: 1
waivers:
  - rule: oss-bucket-public-read-prohibited
    resource: "LegacyBucket"          # ID exato ou glob, ex.: "legacy-*"
    files: ["envs/legacy/**"]          # globs de arquivo opcionais (suporta **)
    reason: "Legacy resource, approved in CAB-1234"
    expires: 2026-09-30
    owner: alice@example.com

  - rule: rds-instance-enabled-tde
    resource: "*"                      # todos os recursos correspondentes
    files: ["sandbox/**"]
    reason: "Sandbox environment does not require TDE"
    # sem expires → isenção permanente (sinalizada por `waiver lint`)
```

| Campo | Significado | Obrigatório |
| --- | --- | --- |
| `rule` | ID curto da regra, ou `*` para todas as regras | Sim |
| `resource` | ID do recurso, exato ou glob | Não (qualquer recurso) |
| `files` | Globs de caminho de arquivo (`*`, `**`) | Não (qualquer arquivo) |
| `reason` | Justificativa | Sim |
| `expires` | `YYYY-MM-DD`; vazio significa permanente | Não (recomendado) |
| `owner` | Pessoa responsável | Não (recomendado) |

Diretivas inline têm precedência sobre as isenções de arquivo para o mesmo recurso.

## Comportamento durante uma varredura

- Isenção **ativa** → a violação é ocultada e contabilizada como `waived` no resumo.
- Isenção **expirada** → a violação é mostrada novamente e, por padrão, faz a build falhar.
- **Sem isenção** → uma violação normal.

```bash
infraguard scan -p pack:aliyun:... template.yaml          # isenções aplicadas automaticamente
infraguard scan ... --show-waived template.yaml           # mostra o que foi isentado
infraguard scan ... --no-waivers template.yaml            # visão completa, ignora todas as isenções
infraguard scan ... --fail-on-expired=false template.yaml # não falha em isenções expiradas
```

Para CI, uma equipe de segurança pode executar `--no-waivers` para ver o quadro completo, ou manter
as isenções mas confiar no `--fail-on-expired` padrão para forçar renovações.

## Governando isenções

```bash
infraguard waiver list    # mostra todas as isenções e seu status
infraguard waiver lint    # encontra motivos ausentes, regras desconhecidas, entradas expiradas
```

Adicione `waiver lint` ao pre-commit ou ao CI para que o próprio arquivo de isenções permaneça saudável.
Consulte a [referência da CLI waiver](../cli/waiver).

## Uma nota sobre segurança

As isenções legitimamente ocultam riscos, por isso são restringidas propositalmente: um `reason` é
obrigatório, isenções expiradas falham por padrão, a saída JSON sempre retém os itens isentos
para auditoria, e o arquivo é revisado via Git. Prefira isenções restritas
(regra + recurso + arquivo) em vez de amplas, e sempre defina uma data de `expires`.
