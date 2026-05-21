package infraguard.rules.terraform.slb_instance_autorenewal_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-instance-autorenewal-check",
	"severity": "low",
	"name": {
		"en": "SLB Instance Auto-Renewal Check",
		"zh": "SLB 实例包年包月开启自动续费",
		"ja": "SLB インスタンス自動更新チェック",
		"de": "SLB-Instanz Auto-Verlängerungsprüfung",
		"es": "Verificación de Renovación Automática de Instancia SLB",
		"fr": "Vérification de Renouvellement Automatique d'Instance SLB",
		"pt": "Verificação de Renovação Automática de Instância SLB"
	},
	"description": {
		"en": "Prepaid SLB instances should have auto-renewal enabled to avoid service interruption.",
		"zh": "包年包月的 SLB 实例开启了自动续费，视为合规。",
		"ja": "プリペイド SLB インスタンスは、サービス中断を避けるために自動更新を有効にする必要があります。",
		"de": "Vorausbezahlte SLB-Instanzen sollten Auto-Verlängerung aktiviert haben, um Dienstunterbrechungen zu vermeiden.",
		"es": "Las instancias SLB prepagadas deben tener renovación automática habilitada para evitar interrupciones del servicio.",
		"fr": "Les instances SLB prépayées doivent avoir le renouvellement automatique activé pour éviter les interruptions de service.",
		"pt": "Instâncias SLB pré-pagas devem ter renovação automática habilitada para evitar interrupção do serviço."
	},
	"reason": {
		"en": "SLB instances without auto-renewal may expire and cause service interruption.",
		"zh": "未开启自动续费的 SLB 实例可能到期并导致服务中断。",
		"ja": "自動更新がない SLB インスタンスは期限切れになり、サービス中断を引き起こす可能性があります。",
		"de": "SLB-Instanzen ohne Auto-Verlängerung können ablaufen und Dienstunterbrechungen verursachen.",
		"es": "Las instancias SLB sin renovación automática pueden expirar y causar interrupción del servicio.",
		"fr": "Les instances SLB sans renouvellement automatique peuvent expirer et causer une interruption de service.",
		"pt": "Instâncias SLB sem renovação automática podem expirar e causar interrupção do serviço."
	},
	"recommendation": {
		"en": "Set renewal_status to 'AutoRenewal' for prepaid (Subscription) SLB instances.",
		"zh": "为包年包月 SLB 实例将 renewal_status 设置为 'AutoRenewal'。",
		"ja": "プリペイド SLB インスタンスの renewal_status を 'AutoRenewal' に設定します。",
		"de": "Setzen Sie renewal_status für vorausbezahlte SLB-Instanzen auf 'AutoRenewal'.",
		"es": "Establezca renewal_status en 'AutoRenewal' para instancias SLB prepagadas (Subscription).",
		"fr": "Définissez renewal_status sur 'AutoRenewal' pour les instances SLB prépayées (Subscription).",
		"pt": "Defina renewal_status como 'AutoRenewal' para instâncias SLB pré-pagas (Subscription)."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

is_subscription(resource) if {
	tf.get_attribute(resource, "payment_type", "") == "Subscription"
}

has_auto_renewal(resource) if {
	tf.get_attribute(resource, "renewal_status", "") == "AutoRenewal"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	is_subscription(resource)
	not has_auto_renewal(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_load_balancer.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
