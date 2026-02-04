---
title: Inicio Rápido
---

# Inicio Rápido

Esta guía le ayudará a comenzar con InfraGuard en solo unos minutos.

## Paso 1: Crear una Plantilla ROS de Ejemplo

Cree un archivo llamado `template.yaml` con el siguiente contenido:

```yaml
ROSTemplateFormatVersion: '2015-09-01'
Description: Sample ECS instance

Resources:
  MyECS:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      ImageId: 'centos_7'
      InstanceType: 'ecs.t5-lc1m1.small'
      AllocatePublicIP: true
      SecurityGroupId: 'sg-xxxxx'
      VpcId: 'vpc-xxxxx'
      VSwitchId: 'vsw-xxxxx'
```

## Paso 2: Ejecutar Su Primer Escaneo

Escanee la plantilla usando una regla integrada:

```bash
infraguard scan template.yaml -p rule:aliyun:ecs-instance-no-public-and-anyip
```

Debería ver una salida que indica que la instancia ECS tiene una IP pública asignada, lo cual es un problema de seguridad.

## Paso 3: Usar un Paquete de Cumplimiento

En lugar de reglas individuales, puede escanear con un paquete de cumplimiento completo:

```bash
infraguard scan template.yaml -p pack:aliyun:security-group-best-practice
```

## Paso 4: Generar un Informe

InfraGuard soporta múltiples formatos de salida:

### Formato Tabla (Predeterminado)

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack
```

### Formato JSON

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format json
```

### Informe HTML

```bash
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --format html -o report.html
```

Abra `report.html` en su navegador para ver un informe interactivo.

## Paso 5: Listar Políticas Disponibles

Para ver todas las reglas y paquetes disponibles:

```bash
# Listar todas las políticas
infraguard policy list

# Obtener detalles sobre una regla específica
infraguard policy get rule:aliyun:ecs-instance-no-public-ip

# Obtener detalles sobre un paquete de cumplimiento
infraguard policy get pack:aliyun:mlps-level-3-pre-check-compliance-pack
```

## Casos de Uso Comunes

### Escanear con Múltiples Políticas

Puede aplicar múltiples políticas en un solo escaneo:

```bash
infraguard scan template.yaml \
  -p rule:aliyun:ecs-instance-no-public-ip \
  -p rule:aliyun:rds-instance-enabled-disk-encryption \
  -p pack:aliyun:quick-start-compliance-pack
```

### Configurar Preferencia de Idioma

InfraGuard soporta 7 idiomas:

```bash
# Salida en español
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang es

# Salida en inglés
infraguard scan template.yaml -p pack:aliyun:quick-start-compliance-pack --lang en

# Otros idiomas soportados: zh (Chino), fr (Francés), de (Alemán), ja (Japonés), pt (Portugués)
```

También puede configurar el idioma permanentemente:

```bash
infraguard config set lang es
```

Códigos de idioma soportados: `en`, `zh`, `es`, `fr`, `de`, `ja`, `pt`. El predeterminado se detecta automáticamente según la configuración regional de su sistema.

## Próximos Pasos

- **Aprender Más**: Lea la [Guía de Usuario](../user-guide/scanning-templates) para información detallada
- **Explorar Políticas**: Navegue por la [Referencia de Políticas](../policies/aliyun/rules) para ver todas las reglas y paquetes disponibles
- **Escribir Políticas Personalizadas**: Consulte la [Guía de Desarrollo](../development/writing-rules) para crear sus propias reglas

## Obtener Ayuda

Si encuentra algún problema:

1. Consulte la página [FAQ](../faq)
2. Revise los mensajes de error cuidadosamente - generalmente incluyen pistas útiles
3. Reporte problemas en [GitHub](https://github.com/aliyun/infraguard/issues)
