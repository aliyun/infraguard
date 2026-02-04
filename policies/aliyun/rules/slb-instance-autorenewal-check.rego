package infraguard.rules.aliyun.slb_instance_autorenewal_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-instance-autorenewal-check",
	"name": {
		"en": "SLB Instance Auto-Renewal Check",
		"zh": "SLB 实例包年包月开启自动续费",
		"ja": "SLB インスタンス自動更新チェック",
		"de": "SLB-Instanz Auto-Verlängerungsprüfung",
		"es": "Verificación de Renovación Automática de Instancia SLB",
		"fr": "Vérification de Renouvellement Automatique d'Instance SLB",
		"pt": "Verificação de Renovação Automática de Instância SLB",
	},
	"severity": "medium",
	"description": {
		"en": "Prepaid SLB instances should have auto-renewal enabled to avoid service interruption.",
		"zh": "包年包月的 SLB 实例开启了自动续费，视为合规。",
		"ja": "プリペイド SLB インスタンスは、サービス中断を避けるために自動更新を有効にする必要があります。",
		"de": "Vorausbezahlte SLB-Instanzen sollten Auto-Verlängerung aktiviert haben, um Dienstunterbrechungen zu vermeiden.",
		"es": "Las instancias SLB prepagadas deben tener renovación automática habilitada para evitar interrupciones del servicio.",
		"fr": "Les instances SLB prépayées doivent avoir le renouvellement automatique activé pour éviter les interruptions de service.",
		"pt": "Instâncias SLB pré-pagas devem ter renovação automática habilitada para evitar interrupção do serviço.",
	},
	"reason": {
		"en": "SLB instances without auto-renewal may expire and cause service interruption.",
		"zh": "未开启自动续费的 SLB 实例可能到期并导致服务中断。",
		"ja": "自動更新がない SLB インスタンスは期限切れになり、サービス中断を引き起こす可能性があります。",
		"de": "SLB-Instanzen ohne Auto-Verlängerung können ablaufen und Dienstunterbrechungen verursachen.",
		"es": "Las instancias SLB sin renovación automática pueden expirar y causar interrupción del servicio.",
		"fr": "Les instances SLB sans renouvellement automatique peuvent expirer et causer une interruption de service.",
		"pt": "Instâncias SLB sem renovação automática podem expirar e causar interrupção do serviço.",
	},
	"recommendation": {
		"en": "Enable auto-renewal for prepaid SLB instances.",
		"zh": "为包年包月 SLB 实例开启自动续费。",
		"ja": "プリペイド SLB インスタンスの自動更新を有効にします。",
		"de": "Aktivieren Sie die Auto-Verlängerung für vorausbezahlte SLB-Instanzen.",
		"es": "Habilite la renovación automática para instancias SLB prepagadas.",
		"fr": "Activez le renouvellement automatique pour les instances SLB prépayées.",
		"pt": "Habilite a renovação automática para instâncias SLB pré-pagas.",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

is_prepaid(resource) if {
	charge_type := helpers.get_property(resource, "InstanceChargeType", "")
	charge_type == "Prepaid"
}

has_autorenewal(resource) if {
	auto_renew := helpers.get_property(resource, "AutoRenew", false)
	auto_renew == true
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	is_prepaid(resource)
	not has_autorenewal(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AutoRenew"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
