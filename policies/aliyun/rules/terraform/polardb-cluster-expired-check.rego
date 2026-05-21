package infraguard.rules.terraform.polardb_cluster_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "polardb-cluster-expired-check",
	"severity": "medium",
	"name": {
		"en": "PolarDB Cluster Expiration Check",
		"zh": "PolarDB 集群到期检查",
		"ja": "PolarDB クラスタの有効期限チェック",
		"de": "PolarDB-Cluster Ablaufprüfung",
		"es": "Verificación de Expiración de Cluster PolarDB",
		"fr": "Vérification d'Expiration du Cluster PolarDB",
		"pt": "Verificação de Expiração de Cluster PolarDB"
	},
	"description": {
		"en": "Prepaid PolarDB clusters should have auto-renewal enabled.",
		"zh": "预付费 PolarDB 集群应开启自动续费，避免业务中断。",
		"ja": "プリペイド PolarDB クラスタは自動更新を有効にする必要があります。",
		"de": "Vorausbezahlte PolarDB-Cluster sollten automatische Verlängerung aktiviert haben.",
		"es": "Los clústeres PolarDB prepagos deben tener renovación automática habilitada.",
		"fr": "Les clusters PolarDB prépayés doivent avoir le renouvellement automatique activé.",
		"pt": "Clusters PolarDB pré-pagos devem ter renovação automática habilitada."
	},
	"reason": {
		"en": "The prepaid PolarDB cluster does not have auto-renewal enabled.",
		"zh": "预付费 PolarDB 集群未开启自动续费。",
		"ja": "プリペイド PolarDB クラスタで自動更新が有効になっていません。",
		"de": "Der vorausbezahlte PolarDB-Cluster hat keine automatische Verlängerung aktiviert.",
		"es": "El clúster PolarDB prepago no tiene renovación automática habilitada.",
		"fr": "Le cluster PolarDB prépayé n'a pas le renouvellement automatique activé.",
		"pt": "O cluster PolarDB pré-pago não tem renovação automática habilitada."
	},
	"recommendation": {
		"en": "Set renewal_status to AutoRenewal for the prepaid PolarDB cluster.",
		"zh": "为预付费 PolarDB 集群将 renewal_status 设置为 AutoRenewal。",
		"ja": "プリペイド PolarDB クラスタの renewal_status を AutoRenewal に設定します。",
		"de": "Setzen Sie renewal_status für den vorausbezahlten PolarDB-Cluster auf AutoRenewal.",
		"es": "Establezca renewal_status en AutoRenewal para el clúster PolarDB prepago.",
		"fr": "Définissez renewal_status sur AutoRenewal pour le cluster PolarDB prépayé.",
		"pt": "Defina renewal_status como AutoRenewal para o cluster PolarDB pré-pago."
	},
	"resource_types": ["alicloud_polardb_cluster"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_polardb_cluster")
	tf.get_attribute(resource, "pay_type", "PostPaid") == "PrePaid"
	tf.get_attribute(resource, "renewal_status", "Normal") != "AutoRenewal"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_polardb_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
