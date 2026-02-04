package infraguard.rules.aliyun.slb_modify_protection_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "slb-modify-protection-check",
	"name": {
		"en": "SLB Modification Protection Enabled",
		"zh": "SLB 实例开启配置修改保护",
		"ja": "SLB 変更保護が有効",
		"de": "SLB Änderungsschutz aktiviert",
		"es": "Protección contra Modificación de SLB Habilitada",
		"fr": "Protection contre la Modification SLB Activée",
		"pt": "Proteção contra Modificação de SLB Habilitada",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that SLB instances have modification protection enabled.",
		"zh": "确保 SLB 实例开启了配置修改保护。",
		"ja": "SLB インスタンスで変更保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass SLB-Instanzen Änderungsschutz aktiviert haben.",
		"es": "Garantiza que las instancias SLB tengan protección contra modificación habilitada.",
		"fr": "Garantit que les instances SLB ont la protection contre la modification activée.",
		"pt": "Garante que as instâncias SLB tenham proteção contra modificação habilitada.",
	},
	"reason": {
		"en": "If modification protection is not enabled, the SLB configuration may be modified accidentally, causing service issues.",
		"zh": "如果未开启配置修改保护，SLB 配置可能会被意外修改，导致服务异常。",
		"ja": "変更保護が有効になっていない場合、SLB 設定が誤って変更され、サービスに問題が発生する可能性があります。",
		"de": "Wenn der Änderungsschutz nicht aktiviert ist, kann die SLB-Konfiguration versehentlich geändert werden, was zu Dienstproblemen führt.",
		"es": "Si la protección contra modificación no está habilitada, la configuración SLB puede modificarse accidentalmente, causando problemas en el servicio.",
		"fr": "Si la protection contre la modification n'est pas activée, la configuration SLB peut être modifiée accidentellement, causant des problèmes de service.",
		"pt": "Se a proteção contra modificação não estiver habilitada, a configuração SLB pode ser modificada acidentalmente, causando problemas no serviço.",
	},
	"recommendation": {
		"en": "Enable modification protection for the SLB instance.",
		"zh": "为 SLB 实例开启配置修改保护功能。",
		"ja": "SLB インスタンスで変更保護を有効にします。",
		"de": "Aktivieren Sie den Änderungsschutz für die SLB-Instanz.",
		"es": "Habilite protección contra modificación para la instancia SLB.",
		"fr": "Activez la protection contre la modification pour l'instance SLB.",
		"pt": "Habilite proteção contra modificação para a instância SLB.",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

is_compliant(resource) if {
	helpers.get_property(resource, "ModificationProtectionStatus", "") == "ConsoleProtection"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ModificationProtectionStatus"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
