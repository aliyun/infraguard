package infraguard.rules.aliyun.slb_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "slb-delete-protection-enabled",
	"name": {
		"en": "SLB Instance Deletion Protection Enabled",
		"zh": "SLB 实例开启释放保护",
		"de": "SLB-Instanz-Löschschutz aktiviert",
		"ja": "SLB インスタンスの削除保護が有効",
		"es": "Protección contra Eliminación de Instancia SLB Habilitada",
		"fr": "Protection contre la Suppression d'Instance SLB Activée",
		"pt": "Proteção contra Exclusão de Instância SLB Habilitada",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that SLB instances have deletion protection enabled.",
		"zh": "确保 SLB 实例开启了释放保护。",
		"ja": "SLB インスタンスで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass SLB-Instanzen den Löschschutz aktiviert haben.",
		"es": "Garantiza que las instancias SLB tengan protección contra eliminación habilitada.",
		"fr": "Garantit que les instances SLB ont la protection contre la suppression activée.",
		"pt": "Garante que as instâncias SLB tenham proteção contra exclusão habilitada.",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the SLB instance may be released accidentally, causing service interruption.",
		"zh": "如果未开启释放保护，SLB 实例可能会被意外释放，导致业务中断。",
		"de": "Wenn der Löschschutz nicht aktiviert ist, kann die SLB-Instanz versehentlich freigegeben werden, was zu Dienstunterbrechungen führt.",
		"ja": "削除保護が有効になっていない場合、SLB インスタンスが誤って解放され、サービス中断が発生する可能性があります。",
		"es": "Si la protección contra eliminación no está habilitada, la instancia SLB puede ser liberada accidentalmente, causando interrupción del servicio.",
		"fr": "Si la protection contre la suppression n'est pas activée, l'instance SLB peut être libérée accidentellement, provoquant une interruption de service.",
		"pt": "Se a proteção contra exclusão não estiver habilitada, a instância SLB pode ser liberada acidentalmente, causando interrupção do serviço.",
	},
	"recommendation": {
		"en": "Enable deletion protection for the SLB instance.",
		"zh": "为 SLB 实例开启释放保护功能。",
		"de": "Aktivieren Sie den Löschschutz für die SLB-Instanz.",
		"ja": "SLB インスタンスで削除保護を有効にします。",
		"es": "Habilite protección contra eliminación para la instancia SLB.",
		"fr": "Activez la protection contre la suppression pour l'instance SLB.",
		"pt": "Habilite proteção contra exclusão para a instância SLB.",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
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
