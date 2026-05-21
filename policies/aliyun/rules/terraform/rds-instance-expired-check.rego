package infraguard.rules.terraform.rds_instance_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-instance-expired-check",
	"severity": "medium",
	"name": {
		"en": "RDS Prepaid Instance Expiration Check",
		"zh": "RDS 预付费实例到期检查",
		"ja": "RDS プリペイドインスタンスの有効期限チェック",
		"de": "RDS Vorausbezahlte Instanz Ablaufprüfung",
		"es": "Verificación de Expiración de Instancia Prepaga RDS",
		"fr": "Vérification d'Expiration d'Instance Prépayée RDS",
		"pt": "Verificação de Expiração de Instância Pré-paga RDS"
	},
	"description": {
		"en": "Prepaid RDS instances should have auto-renewal enabled.",
		"zh": "预付费 RDS 实例应开启自动续费，避免业务中断。",
		"ja": "プリペイド RDS インスタンスは自動更新を有効にする必要があります。",
		"de": "Vorausbezahlte RDS-Instanzen sollten automatische Verlängerung aktiviert haben.",
		"es": "Las instancias RDS prepagas deben tener renovación automática habilitada.",
		"fr": "Les instances RDS prépayées doivent avoir le renouvellement automatique activé.",
		"pt": "Instâncias RDS pré-pagas devem ter renovação automática habilitada."
	},
	"reason": {
		"en": "The prepaid RDS instance does not have auto-renewal enabled.",
		"zh": "预付费 RDS 实例未开启自动续费。",
		"ja": "プリペイド RDS インスタンスで自動更新が有効になっていません。",
		"de": "Die vorausbezahlte RDS-Instanz hat keine automatische Verlängerung aktiviert.",
		"es": "La instancia RDS prepaga no tiene renovación automática habilitada.",
		"fr": "L'instance RDS prépayée n'a pas le renouvellement automatique activé.",
		"pt": "A instância RDS pré-paga não tem renovação automática habilitada."
	},
	"recommendation": {
		"en": "Set auto_renew to true for the prepaid RDS instance.",
		"zh": "为预付费 RDS 实例将 auto_renew 设置为 true。",
		"ja": "プリペイド RDS インスタンスの auto_renew を true に設定します。",
		"de": "Setzen Sie auto_renew für die vorausbezahlte RDS-Instanz auf true.",
		"es": "Establezca auto_renew en true para la instancia RDS prepaga.",
		"fr": "Définissez auto_renew sur true pour l'instance RDS prépayée.",
		"pt": "Defina auto_renew como true para a instância RDS pré-paga."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	tf.get_attribute(resource, "instance_charge_type", "Postpaid") == "Prepaid"
	tf.get_attribute(resource, "auto_renew", false) != true
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
