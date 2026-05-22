package infraguard.rules.terraform.hbase_cluster_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "hbase-cluster-expired-check",
	"severity": "high",
	"name": {
		"en": "HBase Prepaid Instance Expiration Check",
		"zh": "HBase 预付费实例到期检查",
		"ja": "HBase プリペイドインスタンスの有効期限チェック",
		"de": "HBase Vorausbezahlte Instanz Ablaufprufung",
		"es": "Verificacion de Expiracion de Instancia Prepaga HBase",
		"fr": "Verification d'Expiration d'Instance Prepayee HBase",
		"pt": "Verificacao de Expiracao de Instancia Pre-paga HBase"
	},
	"description": {
		"en": "Prepaid HBase instances should have auto-renewal enabled.",
		"zh": "预付费 HBase 实例应开启自动续费，避免业务中断。",
		"ja": "プリペイド HBase インスタンスは自動更新を有効にする必要があります。",
		"de": "Vorausbezahlte HBase-Instanzen sollten automatische Verlangerung aktiviert haben.",
		"es": "Las instancias HBase prepagas deben tener renovacion automatica habilitada.",
		"fr": "Les instances HBase prepayees doivent avoir le renouvellement automatique active.",
		"pt": "Instancias HBase pre-pagas devem ter renovacao automatica habilitada."
	},
	"reason": {
		"en": "The prepaid HBase instance does not have auto-renewal enabled, which may lead to service interruption upon expiration.",
		"zh": "预付费 HBase 实例未开启自动续费，到期后可能导致服务中断。",
		"ja": "プリペイド HBase インスタンスで自動更新が有効になっておらず、有効期限切れ時にサービス中断が発生する可能性があります。",
		"de": "Die vorausbezahlte HBase-Instanz hat keine automatische Verlangerung aktiviert, was bei Ablauf zu Dienstunterbrechungen fuhren kann.",
		"es": "La instancia HBase prepaga no tiene renovacion automatica habilitada, lo que puede causar interrupcion del servicio al expirar.",
		"fr": "L'instance HBase prepayee n'a pas le renouvellement automatique active, ce qui peut entrainer une interruption de service a l'expiration.",
		"pt": "A instancia HBase pre-paga nao tem renovacao automatica habilitada, o que pode causar interrupcao do servico ao expirar."
	},
	"recommendation": {
		"en": "Enable auto-renewal by setting auto_renew_period to a value greater than 0 for the prepaid HBase instance.",
		"zh": "通过将 auto_renew_period 设置为大于 0 的值为预付费 HBase 实例开启自动续费。",
		"ja": "プリペイド HBase インスタンスで auto_renew_period を 0 より大きい値に設定して自動更新を有効にします。",
		"de": "Aktivieren Sie die automatische Verlangerung, indem Sie auto_renew_period auf einen Wert grosser als 0 fur die vorausbezahlte HBase-Instanz setzen.",
		"es": "Habilite la renovacion automatica configurando auto_renew_period a un valor mayor que 0 para la instancia HBase prepaga.",
		"fr": "Activez le renouvellement automatique en definissant auto_renew_period a une valeur superieure a 0 pour l'instance HBase prepayee.",
		"pt": "Habilite renovacao automatica definindo auto_renew_period como um valor maior que 0 para a instancia HBase pre-paga."
	},
	"resource_types": ["alicloud_hbase_instance"],
	"iac_type": "terraform"
}

is_prepaid(resource) if {
	pay_type := tf.get_attribute(resource, "pay_type", "PostPaid")
	pay_type == "PrePaid"
}

is_auto_renew_enabled(resource) if {
	auto_renew_period := tf.get_attribute(resource, "auto_renew_period", 0)
	not tf.is_unknown(auto_renew_period)
	auto_renew_period > 0
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_hbase_instance")
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_hbase_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
