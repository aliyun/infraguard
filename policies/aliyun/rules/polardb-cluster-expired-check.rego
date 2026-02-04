package infraguard.rules.aliyun.polardb_cluster_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "polardb-cluster-expired-check",
	"name": {
		"en": "PolarDB Cluster Expiration Check",
		"zh": "PolarDB 集群到期检查",
		"ja": "PolarDB クラスタの有効期限チェック",
		"de": "PolarDB-Cluster Ablaufprüfung",
		"es": "Verificación de Expiración de Cluster PolarDB",
		"fr": "Vérification d'Expiration du Cluster PolarDB",
		"pt": "Verificação de Expiração de Cluster PolarDB",
	},
	"severity": "high",
	"description": {
		"en": "Prepaid PolarDB clusters should have auto-renewal enabled.",
		"zh": "预付费 PolarDB 集群应开启自动续费，避免业务中断。",
		"ja": "プリペイド PolarDB クラスタは自動更新を有効にする必要があります。",
		"de": "Vorausbezahlte PolarDB-Cluster sollten automatische Verlängerung aktiviert haben.",
		"es": "Los clústeres PolarDB prepagos deben tener renovación automática habilitada.",
		"fr": "Les clusters PolarDB prépayés doivent avoir le renouvellement automatique activé.",
		"pt": "Clusters PolarDB pré-pagos devem ter renovação automática habilitada.",
	},
	"reason": {
		"en": "The prepaid PolarDB cluster does not have auto-renewal enabled.",
		"zh": "预付费 PolarDB 集群未开启自动续费。",
		"ja": "プリペイド PolarDB クラスタで自動更新が有効になっていません。",
		"de": "Der vorausbezahlte PolarDB-Cluster hat keine automatische Verlängerung aktiviert.",
		"es": "El clúster PolarDB prepago no tiene renovación automática habilitada.",
		"fr": "Le cluster PolarDB prépayé n'a pas le renouvellement automatique activé.",
		"pt": "O cluster PolarDB pré-pago não tem renovação automática habilitada.",
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid PolarDB cluster by setting RenewalStatus to AutoRenewal.",
		"zh": "通过将 RenewalStatus 设置为 AutoRenewal 为预付费 PolarDB 集群开启自动续费。",
		"ja": "RenewalStatus を AutoRenewal に設定して、プリペイド PolarDB クラスタで自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlängerung für den vorausbezahlten PolarDB-Cluster, indem Sie RenewalStatus auf AutoRenewal setzen.",
		"es": "Habilite la renovación automática para el clúster PolarDB prepago estableciendo RenewalStatus en AutoRenewal.",
		"fr": "Activez le renouvellement automatique pour le cluster PolarDB prépayé en définissant RenewalStatus sur AutoRenewal.",
		"pt": "Habilite renovação automática para o cluster PolarDB pré-pago definindo RenewalStatus como AutoRenewal.",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_prepaid(resource) if {
	helpers.get_property(resource, "PayType", "Postpaid") == "Prepaid"
}

is_auto_renew_enabled(resource) if {
	status := helpers.get_property(resource, "RenewalStatus", "Normal")
	status == "AutoRenewal"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RenewalStatus"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
