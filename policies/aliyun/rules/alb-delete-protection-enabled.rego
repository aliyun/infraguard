package infraguard.rules.aliyun.alb_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "alb-delete-protection-enabled",
	"name": {
		"en": "ALB Instance Deletion Protection Enabled",
		"zh": "ALB 实例开启释放保护",
		"ja": "ALB インスタンス削除保護が有効",
		"de": "ALB-Instanz Löschschutz aktiviert",
		"es": "Protección de Eliminación de Instancia ALB Habilitada",
		"fr": "Protection contre la Suppression d'Instance ALB Activée",
		"pt": "Proteção contra Exclusão de Instância ALB Habilitada",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ALB instances have deletion protection enabled.",
		"zh": "确保 ALB 实例开启了释放保护。",
		"ja": "ALB インスタンスで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass ALB-Instanzen Löschschutz aktiviert haben.",
		"es": "Garantiza que las instancias ALB tengan protección contra eliminación habilitada.",
		"fr": "Garantit que les instances ALB ont la protection contre la suppression activée.",
		"pt": "Garante que as instâncias ALB tenham proteção contra exclusão habilitada.",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the ALB instance may be released accidentally, causing service interruption.",
		"zh": "如果未开启释放保护，ALB 实例可能会被意外释放，导致业务中断。",
		"ja": "削除保護が有効になっていない場合、ALB インスタンスが誤って解放され、サービス中断が発生する可能性があります。",
		"de": "Wenn der Löschschutz nicht aktiviert ist, kann die ALB-Instanz versehentlich freigegeben werden, was zu Dienstunterbrechungen führt.",
		"es": "Si la protección contra eliminación no está habilitada, la instancia ALB puede ser liberada accidentalmente, causando interrupción del servicio.",
		"fr": "Si la protection contre la suppression n'est pas activée, l'instance ALB peut être libérée accidentellement, entraînant une interruption de service.",
		"pt": "Se a proteção contra exclusão não estiver habilitada, a instância ALB pode ser liberada acidentalmente, causando interrupção do serviço.",
	},
	"recommendation": {
		"en": "Enable deletion protection for the ALB instance.",
		"zh": "为 ALB 实例开启释放保护功能。",
		"ja": "ALB インスタンスの削除保護を有効にします。",
		"de": "Aktivieren Sie den Löschschutz für die ALB-Instanz.",
		"es": "Habilite la protección contra eliminación para la instancia ALB.",
		"fr": "Activez la protection contre la suppression pour l'instance ALB.",
		"pt": "Habilite a proteção contra exclusão para a instância ALB.",
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtectionEnabled", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeletionProtectionEnabled"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
