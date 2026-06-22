---
title: infraguard waiver
---

# infraguard waiver

Gerenciar isenções de regras (supressões). As isenções permitem suprimir conscientemente
violações específicas com um motivo e uma data de expiração opcional. Consulte o
[Guia de isenções](../user-guide/waivers) para entender os conceitos e o formato do arquivo de isenções.

## Subcomandos

### list

Listar todas as isenções e seu status (ativa / expirada / permanente):
```bash
infraguard waiver list
infraguard waiver list --waivers ./path/to/waivers.yaml
```

### lint

Validar o arquivo de isenções — sinaliza motivos ausentes, regras desconhecidas, datas
inválidas ou expiradas:
```bash
infraguard waiver lint
infraguard waiver lint --rules-dir ./policies/rules   # também reconhece regras personalizadas
```

`lint` retorna um código diferente de zero quando há erros (por exemplo, um `reason` ausente),
tornando-o adequado para um hook de pre-commit ou um gate de CI sobre o próprio arquivo de isenções.

## Flags

| Flag | Descrição | Padrão |
| --- | --- | --- |
| `--waivers` | Caminho para o arquivo de isenções | detecção automática de `.infraguard/waivers.yaml` |
| `--rules-dir` | (`lint`) Também tratar as regras sob este diretório como conhecidas | — |

## Flags de scan relacionadas

As isenções são aplicadas durante o `infraguard scan`. As flags relevantes são:

| Flag | Descrição | Padrão |
| --- | --- | --- |
| `--waivers` | Caminho para o arquivo de isenções | detecção automática |
| `--no-waivers` | Ignorar todas as isenções (comentários inline e arquivo) | `false` |
| `--show-waived` | Mostrar violações isentas em vez de ocultá-las | `false` |
| `--fail-on-expired` | Tratar isenções expiradas como violações reais | `true` |

Consulte [infraguard scan](./scan) e o [Guia de isenções](../user-guide/waivers).
