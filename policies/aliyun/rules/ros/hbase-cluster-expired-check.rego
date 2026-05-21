package infraguard.rules.aliyun.hbase_cluster_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "hbase-cluster-expired-check",
	"severity": "high",
	"name": {
		"en": "HBase Cluster Expiration Check",
		"zh": "HBase 集群到期检查",
		"ja": "HBase クラスターの有効期限チェック",
		"de": "HBase-Cluster-Ablaufprüfung",
		"es": "Verificación de Expiración de Clúster HBase",
		"fr": "Vérification d'Expiration du Cluster HBase",
		"pt": "Verificação de Expiração do Cluster HBase"
	},
	"description": {
		"en": "Prepaid HBase clusters should have auto-renewal enabled.",
		"zh": "预付费 HBase 集群应开启自动续费，避免业务中断。",
		"ja": "プリペイド HBase クラスターで自動更新が有効になっている必要があります。",
		"de": "Vorausbezahlte HBase-Cluster sollten automatische Verlängerung aktiviert haben.",
		"es": "Los clústeres HBase prepagados deben tener renovación automática habilitada.",
		"fr": "Les clusters HBase prépayés doivent avoir le renouvellement automatique activé.",
		"pt": "Os clusters HBase pré-pagos devem ter renovação automática habilitada."
	},
	"reason": {
		"en": "The prepaid HBase cluster does not have auto-renewal enabled.",
		"zh": "预付费 HBase 集群未开启自动续费。",
		"ja": "プリペイド HBase クラスターで自動更新が有効になっていません。",
		"de": "Der vorausbezahlte HBase-Cluster hat keine automatische Verlängerung aktiviert.",
		"es": "El clúster HBase prepagado no tiene renovación automática habilitada.",
		"fr": "Le cluster HBase prépayé n'a pas le renouvellement automatique activé.",
		"pt": "O cluster HBase pré-pago não tem renovação automática habilitada."
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid HBase cluster by setting AutoRenewPeriod to a value greater than 0.",
		"zh": "通过将 AutoRenewPeriod 设置为大于 0 的值来开启自动续费。",
		"ja": "AutoRenewPeriod を 0 より大きい値に設定して、プリペイド HBase クラスターの自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlängerung für den vorausbezahlten HBase-Cluster, indem Sie AutoRenewPeriod auf einen Wert größer als 0 setzen.",
		"es": "Habilite la renovación automática para el clúster HBase prepagado estableciendo AutoRenewPeriod en un valor mayor que 0.",
		"fr": "Activez le renouvellement automatique pour le cluster HBase prépayé en définissant AutoRenewPeriod sur une valeur supérieure à 0.",
		"pt": "Habilite a renovação automática para o cluster HBase pré-pago definindo AutoRenewPeriod como um valor maior que 0."
	},
	"resource_types": ["ALIYUN::HBase::Cluster"]
}

is_prepaid(resource) if {
	helpers.get_property(resource, "PayType", "Postpaid") == "Prepaid"
}

is_auto_renew_enabled(resource) if {
	period := helpers.get_property(resource, "AutoRenewPeriod", 0)
	period > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AutoRenewPeriod"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
