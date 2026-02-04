package infraguard.rules.aliyun.ecs_instance_auto_renewal_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instance-auto-renewal-enabled",
	"name": {
		"en": "ECS subscription instance has auto-renewal enabled",
		"zh": "ECS 包年包月实例开启自动续费",
		"ja": "ECS サブスクリプションインスタンスで自動更新が有効",
		"de": "ECS-Abonnement-Instanz hat automatische Verlängerung aktiviert",
		"es": "Instancia de suscripción ECS tiene renovación automática habilitada",
		"fr": "Instance d'abonnement ECS a le renouvellement automatique activé",
		"pt": "Instância de assinatura ECS tem renovação automática habilitada",
	},
	"description": {
		"en": "ECS subscription (prepaid) instances have auto-renewal enabled, considered compliant. Pay-as-you-go instances are not applicable.",
		"zh": "ECS 包年包月的实例开启自动续费，视为合规。按量付费的实例不适用本规则。",
		"ja": "ECS サブスクリプション（プリペイド）インスタンスで自動更新が有効になっている場合、準拠と見なされます。従量課金インスタンスは適用されません。",
		"de": "ECS-Abonnement-Instanzen (vorausbezahlt) haben automatische Verlängerung aktiviert, werden als konform betrachtet. Pay-as-you-go-Instanzen sind nicht anwendbar.",
		"es": "Las instancias de suscripción ECS (prepagadas) tienen renovación automática habilitada, consideradas conformes. Las instancias de pago por uso no son aplicables.",
		"fr": "Les instances d'abonnement ECS (prépayées) ont le renouvellement automatique activé, considérées comme conformes. Les instances à la demande ne sont pas applicables.",
		"pt": "Instâncias de assinatura ECS (pré-pagas) têm renovação automática habilitada, consideradas conformes. Instâncias pay-as-you-go não são aplicáveis.",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
	"reason": {
		"en": "ECS subscription instance does not have auto-renewal enabled",
		"zh": "ECS 包年包月实例未开启自动续费",
		"ja": "ECS サブスクリプションインスタンスで自動更新が有効になっていません",
		"de": "ECS-Abonnement-Instanz hat keine automatische Verlängerung aktiviert",
		"es": "La instancia de suscripción ECS no tiene renovación automática habilitada",
		"fr": "L'instance d'abonnement ECS n'a pas le renouvellement automatique activé",
		"pt": "Instância de assinatura ECS não tem renovação automática habilitada",
	},
	"recommendation": {
		"en": "Enable auto-renewal for subscription instances to avoid service interruption due to expiration",
		"zh": "为订阅实例启用自动续费，避免因到期导致服务中断",
		"ja": "有効期限によるサービス中断を避けるために、サブスクリプションインスタンスで自動更新を有効にします",
		"de": "Aktivieren Sie die automatische Verlängerung für Abonnement-Instanzen, um Dienstunterbrechungen aufgrund von Ablauf zu vermeiden",
		"es": "Habilite la renovación automática para instancias de suscripción para evitar la interrupción del servicio debido a la expiración",
		"fr": "Activez le renouvellement automatique pour les instances d'abonnement pour éviter l'interruption de service due à l'expiration",
		"pt": "Habilite renovação automática para instâncias de assinatura para evitar interrupção do serviço devido à expiração",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Only check subscription instances
	instance_charge_type := helpers.get_property(resource, "InstanceChargeType", "Postpaid")

	# Skip postpaid instances
	not instance_charge_type in ["Postpaid", "PayAsYouGo", "PostPaid", "PayOnDemand"]

	# For subscription instances, check if auto-renewal is enabled
	auto_renew := helpers.get_property(resource, "AutoRenew", "False")
	auto_renew == "False"

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AutoRenew"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
