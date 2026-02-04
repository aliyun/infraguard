package infraguard.rules.aliyun.kms_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "kms-instance-multi-zone",
	"name": {
		"en": "KMS Instance Multi-Zone Deployment",
		"zh": "使用多可用区的 KMS 实例",
		"ja": "KMS インスタンスのマルチゾーン展開",
		"de": "KMS-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia KMS",
		"fr": "Déploiement Multi-Zone de l'Instance KMS",
		"pt": "Implantação Multi-Zona da Instância KMS"
	},
	"severity": "medium",
	"description": {
		"en": "KMS instances should be deployed across at least two availability zones for high availability and disaster recovery.",
		"zh": "使用多可用区的 KMS 实例，视为合规。",
		"ja": "KMS インスタンスは高可用性と災害復旧のために少なくとも 2 つの可用性ゾーンにまたがって展開する必要があります。",
		"de": "KMS-Instanzen sollten für hohe Verfügbarkeit und Disaster Recovery über mindestens zwei Verfügbarkeitszonen hinweg bereitgestellt werden.",
		"es": "Las instancias KMS deben desplegarse en al menos dos zonas de disponibilidad para alta disponibilidad y recuperación ante desastres.",
		"fr": "Les instances KMS doivent être déployées sur au moins deux zones de disponibilité pour une haute disponibilité et une reprise après sinistre.",
		"pt": "As instâncias KMS devem ser implantadas em pelo menos duas zonas de disponibilidade para alta disponibilidade e recuperação de desastres."
	},
	"reason": {
		"en": "The KMS instance is not configured with multiple availability zones, which may affect availability.",
		"zh": "KMS 实例未配置多个可用区，可能影响可用性。",
		"ja": "KMS インスタンスが複数の可用性ゾーンで設定されていないため、可用性に影響を与える可能性があります。",
		"de": "Die KMS-Instanz ist nicht mit mehreren Verfügbarkeitszonen konfiguriert, was die Verfügbarkeit beeinträchtigen kann.",
		"es": "La instancia KMS no está configurada con múltiples zonas de disponibilidad, lo que puede afectar la disponibilidad.",
		"fr": "L'instance KMS n'est pas configurée avec plusieurs zones de disponibilité, ce qui peut affecter la disponibilité.",
		"pt": "A instância KMS não está configurada com múltiplas zonas de disponibilidade, o que pode afetar a disponibilidade."
	},
	"recommendation": {
		"en": "Configure at least two availability zones in the Connection.ZoneIds property to enable multi-zone deployment.",
		"zh": "在 Connection.ZoneIds 属性中配置至少两个可用区，以启用多可用区部署。",
		"ja": "マルチゾーン展開を有効にするために、Connection.ZoneIds プロパティで少なくとも 2 つの可用性ゾーンを設定します。",
		"de": "Konfigurieren Sie mindestens zwei Verfügbarkeitszonen in der Connection.ZoneIds-Eigenschaft, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure al menos dos zonas de disponibilidad en la propiedad Connection.ZoneIds para habilitar el despliegue multi-zona.",
		"fr": "Configurez au moins deux zones de disponibilité dans la propriété Connection.ZoneIds pour activer le déploiement multi-zones.",
		"pt": "Configure pelo menos duas zonas de disponibilidade na propriedade Connection.ZoneIds para habilitar a implantação multi-zona."
	},
	"resource_types": ["ALIYUN::KMS::Instance"],
}

# Check if instance has multiple zones configured
has_multiple_zones(resource) if {
	helpers.has_property(resource, "Connection")
	connection := resource.Properties.Connection
	zone_ids := connection.ZoneIds
	count(zone_ids) >= 2
}

# Deny rule: KMS instances must be deployed in multiple zones
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KMS::Instance")
	not has_multiple_zones(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Connection", "ZoneIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
