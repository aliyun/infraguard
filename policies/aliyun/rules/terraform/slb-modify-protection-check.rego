package infraguard.rules.terraform.slb_modify_protection_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-modify-protection-check",
	"severity": "medium",
	"name": {
		"en": "SLB Modification Protection Enabled",
		"zh": "SLB 实例开启配置修改保护",
		"ja": "SLB 変更保護が有効",
		"de": "SLB Änderungsschutz aktiviert",
		"es": "Protección contra Modificación de SLB Habilitada",
		"fr": "Protection contre la Modification SLB Activée",
		"pt": "Proteção contra Modificação de SLB Habilitada"
	},
	"description": {
		"en": "Ensures that SLB instances have modification protection enabled.",
		"zh": "确保 SLB 实例开启了配置修改保护。",
		"ja": "SLB インスタンスで変更保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass SLB-Instanzen Änderungsschutz aktiviert haben.",
		"es": "Garantiza que las instancias SLB tengan protección contra modificación habilitada.",
		"fr": "Garantit que les instances SLB ont la protection contre la modification activée.",
		"pt": "Garante que as instâncias SLB tenham proteção contra modificação habilitada."
	},
	"reason": {
		"en": "If modification protection is not enabled, the SLB configuration may be modified accidentally, causing service issues.",
		"zh": "如果未开启配置修改保护，SLB 配置可能会被意外修改，导致服务异常。",
		"ja": "変更保護が有効になっていない場合、SLB 設定が誤って変更され、サービスに問題が発生する可能性があります。",
		"de": "Wenn der Änderungsschutz nicht aktiviert ist, kann die SLB-Konfiguration versehentlich geändert werden, was zu Dienstproblemen führt.",
		"es": "Si la protección contra modificación no está habilitada, la configuración SLB puede modificarse accidentalmente, causando problemas en el servicio.",
		"fr": "Si la protection contre la modification n'est pas activée, la configuration SLB peut être modifiée accidentellement, causant des problèmes de service.",
		"pt": "Se a proteção contra modificação não estiver habilitada, a configuração SLB pode ser modificada acidentalmente, causando problemas no serviço."
	},
	"recommendation": {
		"en": "Set modification_protection_status to \"ConsoleProtection\" in the alicloud_slb_load_balancer resource.",
		"zh": "在 alicloud_slb_load_balancer 资源中将 modification_protection_status 设置为 \"ConsoleProtection\"。",
		"ja": "alicloud_slb_load_balancer リソースで modification_protection_status を \"ConsoleProtection\" に設定します。",
		"de": "Setzen Sie modification_protection_status auf \"ConsoleProtection\" in der alicloud_slb_load_balancer-Ressource.",
		"es": "Establezca modification_protection_status en \"ConsoleProtection\" en el recurso alicloud_slb_load_balancer.",
		"fr": "Définissez modification_protection_status sur \"ConsoleProtection\" dans la ressource alicloud_slb_load_balancer.",
		"pt": "Defina modification_protection_status como \"ConsoleProtection\" no recurso alicloud_slb_load_balancer."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

is_protected(resource) if {
	value := tf.get_attribute(resource, "modification_protection_status", "")
	not tf.is_unknown(value)
	value == "ConsoleProtection"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	not is_protected(resource)
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
