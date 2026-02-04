package infraguard.rules.aliyun.eip_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "eip-delete-protection-enabled",
	"name": {
		"en": "EIP Deletion Protection Enabled",
		"zh": "弹性公网 IP 开启删除保护",
		"ja": "EIP 削除保護が有効",
		"de": "EIP-Löschschutz aktiviert",
		"es": "Protección de Eliminación de EIP Habilitada",
		"fr": "Protection contre la Suppression EIP Activée",
		"pt": "Proteção de Exclusão de EIP Habilitada"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that EIP instances have deletion protection enabled.",
		"zh": "确保弹性公网 IP 开启了删除保护。",
		"ja": "EIP インスタンスで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass EIP-Instanzen Löschschutz aktiviert haben.",
		"es": "Garantiza que las instancias EIP tengan protección de eliminación habilitada.",
		"fr": "Garantit que les instances EIP ont la protection contre la suppression activée.",
		"pt": "Garante que as instâncias EIP tenham proteção de exclusão habilitada."
	},
	"reason": {
		"en": "If deletion protection is not enabled, the EIP may be released accidentally, potentially changing the public IP of your services.",
		"zh": "如果未开启删除保护，弹性公网 IP 可能会被意外释放，从而可能导致您的服务公网 IP 发生变化。",
		"ja": "削除保護が有効になっていない場合、EIP が誤って解放され、サービスのパブリック IP が変更される可能性があります。",
		"de": "Wenn der Löschschutz nicht aktiviert ist, kann die EIP versehentlich freigegeben werden, was möglicherweise die öffentliche IP Ihrer Dienste ändert.",
		"es": "Si la protección de eliminación no está habilitada, la EIP puede liberarse accidentalmente, cambiando potencialmente la IP pública de sus servicios.",
		"fr": "Si la protection contre la suppression n'est pas activée, l'EIP peut être libérée accidentellement, ce qui peut modifier l'IP publique de vos services.",
		"pt": "Se a proteção de exclusão não estiver habilitada, o EIP pode ser liberado acidentalmente, potencialmente alterando o IP público dos seus serviços."
	},
	"recommendation": {
		"en": "Enable deletion protection for the EIP instance.",
		"zh": "为弹性公网 IP 开启删除保护功能。",
		"ja": "EIP インスタンスの削除保護を有効にします。",
		"de": "Aktivieren Sie den Löschschutz für die EIP-Instanz.",
		"es": "Habilite la protección de eliminación para la instancia EIP.",
		"fr": "Activez la protection contre la suppression pour l'instance EIP.",
		"pt": "Habilite a proteção de exclusão para a instância EIP."
	},
	"resource_types": ["ALIYUN::VPC::EIP"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::EIP")
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
