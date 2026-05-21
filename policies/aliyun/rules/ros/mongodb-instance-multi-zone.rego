package infraguard.rules.aliyun.mongodb_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "mongodb-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "MongoDB Instance Multi-Zone Deployment",
		"zh": "MongoDB 实例多可用区部署",
		"ja": "MongoDB インスタンスマルチゾーン展開",
		"de": "MongoDB-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia MongoDB",
		"fr": "Déploiement Multi-Zone d'Instance MongoDB",
		"pt": "Implantações Multi-Zona de Instância MongoDB"
	},
	"description": {
		"en": "MongoDB instances should be deployed across multiple availability zones for high availability.",
		"zh": "MongoDB 实例应部署在多个可用区。",
		"ja": "MongoDB インスタンスは高可用性のために複数の可用性ゾーンに展開する必要があります。",
		"de": "MongoDB-Instanzen sollten über mehrere Verfügbarkeitszonen hinweg für Hochverfügbarkeit bereitgestellt werden.",
		"es": "Las instancias MongoDB deben desplegarse en múltiples zonas de disponibilidad para alta disponibilidad.",
		"fr": "Les instances MongoDB doivent être déployées sur plusieurs zones de disponibilité pour une haute disponibilité.",
		"pt": "As instâncias MongoDB devem ser implantadas em múltiplas zonas de disponibilidade para alta disponibilidade."
	},
	"reason": {
		"en": "The MongoDB instance is not configured with a secondary or hidden zone.",
		"zh": "MongoDB 实例未配置备用可用区或隐藏可用区。",
		"ja": "MongoDB インスタンスにセカンダリゾーンまたは非表示ゾーンが設定されていません。",
		"de": "Die MongoDB-Instanz ist nicht mit einer sekundären oder versteckten Zone konfiguriert.",
		"es": "La instancia MongoDB no está configurada con una zona secundaria u oculta.",
		"fr": "L'instance MongoDB n'est pas configurée avec une zone secondaire ou cachée.",
		"pt": "A instância MongoDB não está configurada com uma zona secundária ou oculta."
	},
	"recommendation": {
		"en": "Configure SecondaryZoneId or HiddenZoneId to enable multi-zone deployment.",
		"zh": "配置 SecondaryZoneId 或 HiddenZoneId 以启用多可用区部署。",
		"ja": "SecondaryZoneId または HiddenZoneId を設定してマルチゾーン展開を有効にします。",
		"de": "Konfigurieren Sie SecondaryZoneId oder HiddenZoneId, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure SecondaryZoneId o HiddenZoneId para habilitar el despliegue multi-zona.",
		"fr": "Configurez SecondaryZoneId ou HiddenZoneId pour activer le déploiement multi-zone.",
		"pt": "Configure SecondaryZoneId ou HiddenZoneId para habilitar a implantação multi-zona."
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"]
}

# Check if instance is multi-zone
is_multi_zone(resource) if {
	# Check if SecondaryZoneId is present
	object.get(resource.Properties, "SecondaryZoneId", "") != ""
}

is_multi_zone(resource) if {
	# Check if HiddenZoneId is present
	object.get(resource.Properties, "HiddenZoneId", "") != ""
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
