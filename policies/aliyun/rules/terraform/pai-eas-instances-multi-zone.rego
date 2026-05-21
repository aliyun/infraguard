package infraguard.rules.terraform.pai_eas_instances_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "pai-eas-instances-multi-zone",
	"severity": "medium",
	"name": {
		"en": "PAI EAS Instance Multi-Zone Deployment",
		"zh": "PAI EAS 实例多可用区部署",
		"ja": "PAI EAS インスタンスマルチゾーン展開",
		"de": "PAI EAS-Instanz Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona de Instancia PAI EAS",
		"fr": "Déploiement Multi-Zone d'Instance PAI EAS",
		"pt": "Implantação Multi-Zona de Instância PAI EAS"
	},
	"description": {
		"en": "Ensures that PAI EAS instances are deployed across multiple zones for high availability.",
		"zh": "确保 PAI EAS 实例部署在多个可用区以实现高可用性。",
		"ja": "PAI EAS インスタンスが高可用性のために複数のゾーンに展開されていることを確認します。",
		"de": "Stellt sicher, dass PAI EAS-Instanzen über mehrere Zonen hinweg für hohe Verfügbarkeit bereitgestellt werden.",
		"es": "Garantiza que las instancias PAI EAS se implementen en múltiples zonas para alta disponibilidad.",
		"fr": "Garantit que les instances PAI EAS sont déployées sur plusieurs zones pour une haute disponibilité.",
		"pt": "Garante que as instâncias PAI EAS sejam implantadas em múltiplas zonas para alta disponibilidade."
	},
	"reason": {
		"en": "Multi-zone deployment ensures service availability during availability zone failures.",
		"zh": "多可用区部署可确保在可用区故障期间的服务可用性。",
		"ja": "マルチゾーン展開により、可用性ゾーンの障害中でもサービスの可用性が確保されます。",
		"de": "Multi-Zonen-Bereitstellung gewährleistet die Dienstverfügbarkeit während Ausfällen von Verfügbarkeitszonen.",
		"es": "La implementación multi-zona garantiza la disponibilidad del servicio durante fallos de zona de disponibilidad.",
		"fr": "Le déploiement multi-zone garantit la disponibilité du service pendant les pannes de zone de disponibilité.",
		"pt": "A implantação multi-zona garante a disponibilidade do serviço durante falhas de zona de disponibilidade."
	},
	"recommendation": {
		"en": "Set replicas to at least 2 for the PAI EAS service to enable multi-zone deployment.",
		"zh": "将 PAI EAS 服务的 replicas 设置为至少 2 以启用多可用区部署。",
		"ja": "マルチゾーン展開を有効にするには、PAI EAS サービスの replicas を少なくとも 2 に設定します。",
		"de": "Setzen Sie replicas für den PAI EAS-Service auf mindestens 2, um Multi-Zonen-Bereitstellung zu aktivieren.",
		"es": "Establezca replicas en al menos 2 para el servicio PAI EAS para habilitar la implementación multi-zona.",
		"fr": "Définissez replicas sur au moins 2 pour le service PAI EAS afin d'activer le déploiement multi-zone.",
		"pt": "Defina replicas como pelo menos 2 para o serviço PAI EAS para habilitar implantação multi-zona."
	},
	"resource_types": ["alicloud_pai_service"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_pai_service")
	replicas := tf.get_attribute(resource, "replicas", 1)
	replicas < 2
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_pai_service.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
