package infraguard.rules.terraform.mongodb_cluster_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-cluster-expired-check",
	"severity": "medium",
	"name": {
		"en": "MongoDB Instance Expiration Check",
		"zh": "MongoDB 实例到期检查",
		"ja": "MongoDB インスタンスの有効期限チェック",
		"de": "MongoDB-Instanz-Ablaufprüfung",
		"es": "Verificación de Expiración de Instancia MongoDB",
		"fr": "Vérification d'Expiration de l'Instance MongoDB",
		"pt": "Verificação de Expiração da Instância MongoDB"
	},
	"description": {
		"en": "Prepaid MongoDB instances should have auto-renewal enabled to avoid service disruption.",
		"zh": "预付费 MongoDB 实例应开启自动续费，避免业务中断。",
		"ja": "プリペイド MongoDB インスタンスで自動更新が有効になっている必要があります。",
		"de": "Vorausbezahlte MongoDB-Instanzen sollten automatische Verlängerung aktiviert haben.",
		"es": "Las instancias MongoDB prepagadas deben tener renovación automática habilitada.",
		"fr": "Les instances MongoDB prépayées doivent avoir le renouvellement automatique activé.",
		"pt": "As instâncias MongoDB pré-pagas devem ter renovação automática habilitada."
	},
	"reason": {
		"en": "The prepaid MongoDB instance does not have auto-renewal enabled.",
		"zh": "预付费 MongoDB 实例未开启自动续费。",
		"ja": "プリペイド MongoDB インスタンスで自動更新が有効になっていません。",
		"de": "Die vorausbezahlte MongoDB-Instanz hat keine automatische Verlängerung aktiviert.",
		"es": "La instancia MongoDB prepagada no tiene renovación automática habilitada.",
		"fr": "L'instance MongoDB prépayée n'a pas le renouvellement automatique activé.",
		"pt": "A instância MongoDB pré-paga não tem renovação automática habilitada."
	},
	"recommendation": {
		"en": "Set auto_renew to true for prepaid MongoDB instances.",
		"zh": "为预付费 MongoDB 实例将 auto_renew 设置为 true。",
		"ja": "AutoRenew を true に設定して、プリペイド MongoDB インスタンスの自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlängerung für die vorausbezahlte MongoDB-Instanz, indem Sie AutoRenew auf true setzen.",
		"es": "Habilite la renovación automática para la instancia MongoDB prepagada estableciendo AutoRenew en true.",
		"fr": "Activez le renouvellement automatique pour l'instance MongoDB prépayée en définissant AutoRenew sur true.",
		"pt": "Habilite a renovação automática para a instância MongoDB pré-paga definindo AutoRenew como true."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	tf.get_attribute(resource, "instance_charge_type", "PostPaid") == "PrePaid"
	tf.get_attribute(resource, "auto_renew", false) != true
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
