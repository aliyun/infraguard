package infraguard.rules.aliyun.mse_gateway_multi_availability_area_architecture_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "mse-gateway-multi-availability-area-architecture-check",
	"severity": "medium",
	"name": {
		"en": "MSE Gateway Multi-Availability Zone Deployment",
		"zh": "MSE 云原生网关部署在多可用区",
		"ja": "MSE ゲートウェイマルチ可用性ゾーン展開",
		"de": "MSE-Gateway Multi-Verfügbarkeitszonen-Bereitstellung",
		"es": "Implementación Multi-Zona de Disponibilidad de Puerta de Enlace MSE",
		"fr": "Déploiement Multi-Zone de Disponibilité de la Passerelle MSE",
		"pt": "Implantação Multi-Zona de Disponibilidade do Gateway MSE"
	},
	"description": {
		"en": "MSE gateways should be deployed across multiple availability zones by configuring a backup VSwitch.",
		"zh": "MSE 云原生网关部署在多可用区，视为合规。",
		"ja": "MSE ゲートウェイは、バックアップ VSwitch を設定することで、複数の可用性ゾーンに展開する必要があります。",
		"de": "MSE-Gateways sollten durch Konfigurieren eines Backup-VSwitch über mehrere Verfügbarkeitszonen hinweg bereitgestellt werden.",
		"es": "Las puertas de enlace MSE deben implementarse en múltiples zonas de disponibilidad configurando un VSwitch de respaldo.",
		"fr": "Les passerelles MSE doivent être déployées sur plusieurs zones de disponibilité en configurant un VSwitch de sauvegarde.",
		"pt": "Os gateways MSE devem ser implantados em múltiplas zonas de disponibilidade configurando um VSwitch de backup."
	},
	"reason": {
		"en": "The MSE gateway does not have a backup VSwitch configured, which may affect availability.",
		"zh": "MSE 网关未配置备用交换机，可能影响可用性。",
		"ja": "MSE ゲートウェイにバックアップ VSwitch が設定されていないため、可用性に影響を与える可能性があります。",
		"de": "Das MSE-Gateway hat keinen Backup-VSwitch konfiguriert, was die Verfügbarkeit beeinträchtigen kann.",
		"es": "La puerta de enlace MSE no tiene un VSwitch de respaldo configurado, lo que puede afectar la disponibilidad.",
		"fr": "La passerelle MSE n'a pas de VSwitch de sauvegarde configuré, ce qui peut affecter la disponibilité.",
		"pt": "O gateway MSE não tem um VSwitch de backup configurado, o que pode afetar a disponibilidade."
	},
	"recommendation": {
		"en": "Configure a backup VSwitch by setting the BackupVSwitchId property to enable multi-zone deployment.",
		"zh": "通过设置 BackupVSwitchId 属性配置备用交换机，以启用多可用区部署。",
		"ja": "BackupVSwitchId プロパティを設定してバックアップ VSwitch を設定し、マルチゾーン展開を有効にします。",
		"de": "Konfigurieren Sie einen Backup-VSwitch, indem Sie die Eigenschaft BackupVSwitchId setzen, um Multi-Zonen-Bereitstellung zu aktivieren.",
		"es": "Configure un VSwitch de respaldo estableciendo la propiedad BackupVSwitchId para habilitar la implementación multi-zona.",
		"fr": "Configurez un VSwitch de sauvegarde en définissant la propriété BackupVSwitchId pour activer le déploiement multi-zone.",
		"pt": "Configure um VSwitch de backup definindo a propriedade BackupVSwitchId para habilitar a implantação multi-zona."
	},
	"resource_types": ["ALIYUN::MSE::Gateway"]
}

# Check if gateway has backup VSwitch
has_backup_vswitch(resource) if {
	helpers.has_property(resource, "BackupVSwitchId")
	backup_vswitch := resource.Properties.BackupVSwitchId
	backup_vswitch != ""
}

# Deny rule: MSE gateways should have backup VSwitch
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Gateway")
	not has_backup_vswitch(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "BackupVSwitchId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
