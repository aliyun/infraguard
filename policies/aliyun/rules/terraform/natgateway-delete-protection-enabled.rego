package infraguard.rules.terraform.natgateway_delete_protection_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "natgateway-delete-protection-enabled",
	"severity": "high",
	"name": {
		"en": "NAT Gateway Deletion Protection Enabled",
		"zh": "NAT 网关开启释放保护",
		"ja": "NAT ゲートウェイ削除保護が有効",
		"de": "NAT-Gateway Löschschutz aktiviert",
		"es": "Protección de Eliminación de Puerta de Enlace NAT Habilitada",
		"fr": "Protection contre la Suppression de Passerelle NAT Activée",
		"pt": "Proteção contra Exclusão do Gateway NAT Habilitada"
	},
	"description": {
		"en": "Ensures that NAT gateway instances have deletion protection enabled.",
		"zh": "确保 NAT 网关实例开启了释放保护。",
		"ja": "NAT ゲートウェイインスタンスで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass NAT-Gateway-Instanzen Löschschutz aktiviert haben.",
		"es": "Garantiza que las instancias de puerta de enlace NAT tengan protección contra eliminación habilitada.",
		"fr": "Garantit que les instances de passerelle NAT ont la protection contre la suppression activée.",
		"pt": "Garante que as instâncias do gateway NAT tenham proteção contra exclusão habilitada."
	},
	"reason": {
		"en": "If deletion protection is not enabled, the NAT gateway may be released accidentally, causing network disruption.",
		"zh": "如果未开启释放保护，NAT 网关可能会被意外释放，导致网络中断。",
		"ja": "削除保護が有効になっていない場合、NAT ゲートウェイが誤って解放され、ネットワーク中断が発生する可能性があります。",
		"de": "Wenn der Löschschutz nicht aktiviert ist, kann das NAT-Gateway versehentlich freigegeben werden, was zu Netzwerkunterbrechungen führt.",
		"es": "Si la protección contra eliminación no está habilitada, la puerta de enlace NAT puede ser liberada accidentalmente, causando interrupción de red.",
		"fr": "Si la protection contre la suppression n'est pas activée, la passerelle NAT peut être libérée accidentellement, entraînant une interruption réseau.",
		"pt": "Se a proteção contra exclusão não estiver habilitada, o gateway NAT pode ser liberado acidentalmente, causando interrupção de rede."
	},
	"recommendation": {
		"en": "Enable deletion protection for the NAT gateway instance.",
		"zh": "为 NAT 网关实例开启释放保护功能。",
		"ja": "NAT ゲートウェイインスタンスの削除保護を有効にします。",
		"de": "Aktivieren Sie den Löschschutz für die NAT-Gateway-Instanz.",
		"es": "Habilite la protección contra eliminación para la instancia de puerta de enlace NAT.",
		"fr": "Activez la protection contre la suppression pour l'instance de passerelle NAT.",
		"pt": "Habilite a proteção contra exclusão para a instância do gateway NAT."
	},
	"resource_types": ["alicloud_nat_gateway"],
	"iac_type": "terraform"
}

is_compliant(resource) if {
	tf.get_attribute(resource, "deletion_protection", false) == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_nat_gateway")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_nat_gateway.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
