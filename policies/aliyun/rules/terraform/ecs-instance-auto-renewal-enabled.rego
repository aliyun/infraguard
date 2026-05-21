package infraguard.rules.terraform.ecs_instance_auto_renewal_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-instance-auto-renewal-enabled",
	"severity": "medium",
	"name": {
		"en": "ECS subscription instance has auto-renewal enabled",
		"zh": "ECS 包年包月实例开启自动续费",
		"ja": "ECS サブスクリプションインスタンスで自動更新が有効",
		"de": "ECS-Abonnement-Instanz hat automatische Verlängerung aktiviert",
		"es": "Instancia de suscripción ECS tiene renovación automática habilitada",
		"fr": "Instance d'abonnement ECS a le renouvellement automatique activé",
		"pt": "Instância de assinatura ECS tem renovação automática habilitada"
	},
	"description": {
		"en": "ECS subscription (prepaid) instances have auto-renewal enabled, considered compliant. Pay-as-you-go instances are not applicable.",
		"zh": "ECS 包年包月的实例开启自动续费，视为合规。按量付费的实例不适用本规则。",
		"ja": "ECS サブスクリプション（プリペイド）インスタンスで自動更新が有効になっている場合、準拠と見なされます。従量課金インスタンスは適用されません。",
		"de": "ECS-Abonnement-Instanzen (vorausbezahlt) haben automatische Verlängerung aktiviert, werden als konform betrachtet. Pay-as-you-go-Instanzen sind nicht anwendbar.",
		"es": "Las instancias de suscripción ECS (prepagadas) tienen renovación automática habilitada, consideradas conformes. Las instancias de pago por uso no son aplicables.",
		"fr": "Les instances d'abonnement ECS (prépayées) ont le renouvellement automatique activé, considérées comme conformes. Les instances à la demande ne sont pas applicables.",
		"pt": "Instâncias de assinatura ECS (pré-pagas) têm renovação automática habilitada, consideradas conformes. Instâncias pay-as-you-go não são aplicáveis."
	},
	"reason": {
		"en": "ECS subscription instance does not have auto-renewal enabled",
		"zh": "ECS 包年包月实例未开启自动续费",
		"ja": "ECS サブスクリプションインスタンスで自動更新が有効になっていません",
		"de": "ECS-Abonnement-Instanz hat keine automatische Verlängerung aktiviert",
		"es": "La instancia de suscripción ECS no tiene renovación automática habilitada",
		"fr": "L'instance d'abonnement ECS n'a pas le renouvellement automatique activé",
		"pt": "Instância de assinatura ECS não tem renovação automática habilitada"
	},
	"recommendation": {
		"en": "Enable auto-renewal for subscription instances to avoid service interruption due to expiration",
		"zh": "为订阅实例启用自动续费，避免因到期导致服务中断",
		"ja": "有効期限によるサービス中断を避けるために、サブスクリプションインスタンスで自動更新を有効にします",
		"de": "Aktivieren Sie die automatische Verlängerung für Abonnement-Instanzen, um Dienstunterbrechungen aufgrund von Ablauf zu vermeiden",
		"es": "Habilite la renovación automática para instancias de suscripción para evitar la interrupción del servicio debido a la expiración",
		"fr": "Activez le renouvellement automatique pour les instances d'abonnement pour éviter l'interruption de service due à l'expiration",
		"pt": "Habilite renovação automática para instâncias de assinatura para evitar interrupção do serviço devido à expiração"
	},
	"resource_types": ["alicloud_instance"],
	"iac_type": "terraform"
}

violation_for(name) := {
	"id": rule_meta.id,
	"resource_id": sprintf("alicloud_instance.%s", [name]),
	"meta": {
		"severity": rule_meta.severity,
		"reason": rule_meta.reason,
		"recommendation": rule_meta.recommendation,
	},
}

is_prepaid(resource) if {
	charge_type := tf.get_attribute(resource, "instance_charge_type", "PostPaid")
	not tf.is_unknown(charge_type)
	not charge_type in {"PostPaid", "Postpaid", "PayAsYouGo", "PayOnDemand"}
}

has_auto_renewal(resource) if {
	auto_renew := tf.get_attribute(resource, "auto_renew", false)
	not tf.is_unknown(auto_renew)
	auto_renew == true
}

has_auto_renewal(resource) if {
	renewal_status := tf.get_attribute(resource, "renewal_status", "")
	not tf.is_unknown(renewal_status)
	renewal_status == "AutoRenewal"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	is_prepaid(resource)
	not has_auto_renewal(resource)
	violation := violation_for(name)
}
