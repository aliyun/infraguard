package infraguard.rules.aliyun.natgateway_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "natgateway-delete-protection-enabled",
	"name": {
		"en": "NAT Gateway Deletion Protection Enabled",
		"zh": "NAT 网关启用释放保护",
		"ja": "NAT ゲートウェイ削除保護が有効",
		"de": "NAT-Gateway Löschschutz aktiviert",
		"es": "Protección de Eliminación de Puerta de Enlace NAT Habilitada",
		"fr": "Protection contre la Suppression de la Passerelle NAT Activée",
		"pt": "Proteção contra Exclusão do Gateway NAT Habilitada",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that NAT Gateways have deletion protection enabled.",
		"zh": "确保 NAT 网关开启了释放保护。",
		"ja": "NAT ゲートウェイで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass NAT-Gateways Löschschutz aktiviert haben.",
		"es": "Garantiza que las puertas de enlace NAT tengan protección contra eliminación habilitada.",
		"fr": "Garantit que les passerelles NAT ont la protection contre la suppression activée.",
		"pt": "Garante que os gateways NAT tenham proteção contra exclusão habilitada.",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the NAT Gateway may be released accidentally, causing loss of internet connectivity for resources in the VPC.",
		"zh": "如果未开启释放保护，NAT 网关可能会被意外释放，导致 VPC 内资源失去互联网连接。",
		"ja": "削除保護が有効になっていない場合、NAT ゲートウェイが誤って解放され、VPC 内のリソースがインターネット接続を失う可能性があります。",
		"de": "Wenn der Löschschutz nicht aktiviert ist, kann das NAT-Gateway versehentlich freigegeben werden, was zu einem Verlust der Internetverbindung für Ressourcen im VPC führt.",
		"es": "Si la protección contra eliminación no está habilitada, la puerta de enlace NAT puede ser liberada accidentalmente, causando pérdida de conectividad a Internet para recursos en el VPC.",
		"fr": "Si la protection contre la suppression n'est pas activée, la passerelle NAT peut être libérée accidentellement, entraînant une perte de connectivité Internet pour les ressources dans le VPC.",
		"pt": "Se a proteção contra exclusão não estiver habilitada, o gateway NAT pode ser liberado acidentalmente, causando perda de conectividade com a Internet para recursos no VPC.",
	},
	"recommendation": {
		"en": "Enable deletion protection for the NAT Gateway.",
		"zh": "为 NAT 网关开启释放保护功能。",
		"ja": "NAT ゲートウェイの削除保護を有効にします。",
		"de": "Aktivieren Sie den Löschschutz für das NAT-Gateway.",
		"es": "Habilite la protección contra eliminación para la puerta de enlace NAT.",
		"fr": "Activez la protection contre la suppression pour la passerelle NAT.",
		"pt": "Habilite a proteção contra exclusão para o gateway NAT.",
	},
	"resource_types": ["ALIYUN::VPC::NatGateway"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::NatGateway")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeletionProtection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
