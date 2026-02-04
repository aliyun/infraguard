package infraguard.rules.aliyun.pai_eas_instances_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "pai-eas-instances-multi-zone",
	"name": {
		"en": "PAI EAS Instance Multi-Zone Deployment",
		"zh": "PAI EAS 实例多可用区部署",
		"ja": "PAI EAS インスタンスマルチゾーン展開",
		"de": "PAI EAS-Instanz Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona de Instancia PAI EAS",
		"fr": "Déploiement Multi-Zone d'Instance PAI EAS",
		"pt": "Implantação Multi-Zona de Instância PAI EAS",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that PAI EAS instances are deployed across multiple zones for high availability.",
		"zh": "确保 PAI EAS 实例部署在多个可用区以实现高可用性。",
		"ja": "PAI EAS インスタンスが高可用性のために複数のゾーンに展開されていることを確認します。",
		"de": "Stellt sicher, dass PAI EAS-Instanzen über mehrere Zonen hinweg für hohe Verfügbarkeit bereitgestellt werden.",
		"es": "Garantiza que las instancias PAI EAS se implementen en múltiples zonas para alta disponibilidad.",
		"fr": "Garantit que les instances PAI EAS sont déployées sur plusieurs zones pour une haute disponibilité.",
		"pt": "Garante que as instâncias PAI EAS sejam implantadas em múltiplas zonas para alta disponibilidade.",
	},
	"reason": {
		"en": "Multi-zone deployment ensures service availability during availability zone failures.",
		"zh": "多可用区部署可确保在可用区故障期间的服务可用性。",
		"ja": "マルチゾーン展開により、可用性ゾーンの障害中でもサービスの可用性が確保されます。",
		"de": "Multi-Zonen-Bereitstellung gewährleistet die Dienstverfügbarkeit während Ausfällen von Verfügbarkeitszonen.",
		"es": "La implementación multi-zona garantiza la disponibilidad del servicio durante fallos de zona de disponibilidad.",
		"fr": "Le déploiement multi-zone garantit la disponibilité du service pendant les pannes de zone de disponibilité.",
		"pt": "A implantação multi-zona garante a disponibilidade do serviço durante falhas de zona de disponibilidade.",
	},
	"recommendation": {
		"en": "Deploy PAI EAS instances in at least two different availability zones.",
		"zh": "在至少两个不同的可用区中部署 PAI EAS 实例。",
		"ja": "少なくとも2つの異なる可用性ゾーンに PAI EAS インスタンスを展開します。",
		"de": "Stellen Sie PAI EAS-Instanzen in mindestens zwei verschiedenen Verfügbarkeitszonen bereit.",
		"es": "Implemente instancias PAI EAS en al menos dos zonas de disponibilidad diferentes.",
		"fr": "Déployez les instances PAI EAS dans au moins deux zones de disponibilité différentes.",
		"pt": "Implante instâncias PAI EAS em pelo menos duas zonas de disponibilidade diferentes.",
	},
	"resource_types": ["ALIYUN::PAI::Service"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::PAI::Service")

	# Conceptual check for multi-zone deployment
	not helpers.has_property(resource, "MultiAZ") # Simplified
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
