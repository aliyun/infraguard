---
title: infraguard waiver
---

# infraguard waiver

Gestionar exenciones de reglas (supresiones). Las exenciones le permiten suprimir
conscientemente violaciones específicas con un motivo y una fecha de caducidad
opcional. Consulte la [guía de Exenciones](../user-guide/waivers) para conocer los
conceptos y el formato del archivo de exenciones.

## Subcomandos

### list

Listar todas las exenciones y su estado (activa / caducada / permanente):
```bash
infraguard waiver list
infraguard waiver list --waivers ./path/to/waivers.yaml
```

### lint

Validar el archivo de exenciones — señala motivos faltantes, reglas desconocidas y
fechas inválidas o caducadas:
```bash
infraguard waiver lint
infraguard waiver lint --rules-dir ./policies/rules   # también reconoce reglas personalizadas
```

`lint` finaliza con un código distinto de cero cuando hay errores (por ejemplo, un
`reason` faltante), lo que lo hace adecuado para un hook de pre-commit o una puerta
de CI sobre el propio archivo de exenciones.

## Flags

| Flag | Descripción | Predeterminado |
| --- | --- | --- |
| `--waivers` | Ruta al archivo de exenciones | autodetectar `.infraguard/waivers.yaml` |
| `--rules-dir` | (`lint`) También tratar las reglas bajo este directorio como conocidas | — |

## Flags relacionados de scan

Las exenciones se aplican durante `infraguard scan`. Los flags relevantes son:

| Flag | Descripción | Predeterminado |
| --- | --- | --- |
| `--waivers` | Ruta al archivo de exenciones | autodetectar |
| `--no-waivers` | Ignorar todas las exenciones (comentarios en línea y archivo) | `false` |
| `--show-waived` | Mostrar las violaciones exentas en lugar de ocultarlas | `false` |
| `--fail-on-expired` | Tratar las exenciones caducadas como violaciones reales | `true` |

Consulte [infraguard scan](./scan) y la [guía de Exenciones](../user-guide/waivers).
