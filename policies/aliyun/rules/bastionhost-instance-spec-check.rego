package infraguard.rules.aliyun.bastionhost_instance_spec_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "bastionhost-instance-spec-check",
	"severity": "medium",
	"name": {
		"en": "BastionHost Instance Multi-Zone Spec Check",
		"zh": "使用多可用区部署的堡垒机版本",
		"ja": "BastionHost インスタンスマルチゾーン仕様チェック",
		"de": "BastionHost-Instanz Multi-Zone-Spezifikationsprüfung",
		"es": "Verificación de Especificación Multi-Zona de Instancia BastionHost",
		"fr": "Vérification de Spécification Multi-Zone d'Instance BastionHost",
		"pt": "Verificação de Especificação Multi-Zona de Instância BastionHost"
	},
	"description": {
		"en": "The BastionHost instance should use the Enterprise version which supports multi-zone deployment.",
		"zh": "使用多可用区部署的企业双擎或者国密版堡垒机，保障稳定性，视为合规。",
		"ja": "BastionHost インスタンスは、マルチゾーン展開をサポートするエンタープライズバージョンを使用する必要があります。",
		"de": "Die BastionHost-Instanz sollte die Enterprise-Version verwenden, die Multi-Zone-Bereitstellung unterstützt.",
		"es": "La instancia BastionHost debe usar la versión Enterprise que admite despliegue multi-zona.",
		"fr": "L'instance BastionHost doit utiliser la version Enterprise qui prend en charge le déploiement multi-zone.",
		"pt": "A instância BastionHost deve usar a versão Enterprise que suporta implantação multi-zona."
	},
	"reason": {
		"en": "The BastionHost instance is using the Basic version which implies single-zone deployment.",
		"zh": "堡垒机实例使用的是不支持多可用区部署的基础版。",
		"ja": "BastionHost インスタンスはシングルゾーン展開を意味するベーシックバージョンを使用しています。",
		"de": "Die BastionHost-Instanz verwendet die Basic-Version, was eine Single-Zone-Bereitstellung impliziert.",
		"es": "La instancia BastionHost está usando la versión Basic que implica despliegue de zona única.",
		"fr": "L'instance BastionHost utilise la version Basic qui implique un déploiement en zone unique.",
		"pt": "A instância BastionHost está usando a versão Basic que implica implantação de zona única."
	},
	"recommendation": {
		"en": "Upgrade the BastionHost instance to the Enterprise version.",
		"zh": "将堡垒机实例升级到企业版。",
		"ja": "BastionHost インスタンスをエンタープライズバージョンにアップグレードします。",
		"de": "Aktualisieren Sie die BastionHost-Instanz auf die Enterprise-Version.",
		"es": "Actualice la instancia BastionHost a la versión Enterprise.",
		"fr": "Mettez à niveau l'instance BastionHost vers la version Enterprise.",
		"pt": "Atualize a instância BastionHost para a versão Enterprise."
	},
	"resource_types": ["ALIYUN::BastionHost::Instance"]
}

# Check if instance is Enterprise version
is_enterprise(resource) if {
	resource.Properties.Version == "Enterprise"
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_enterprise(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Version"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
