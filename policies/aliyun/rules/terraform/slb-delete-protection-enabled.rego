package infraguard.rules.terraform.slb_delete_protection_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-delete-protection-enabled",
	"severity": "high",
	"name": {
		"en": "SLB Instance Deletion Protection Enabled",
		"zh": "SLB 实例开启释放保护",
		"ja": "SLB インスタンスの削除保護が有効",
		"de": "SLB-Instanz-Löschschutz aktiviert",
		"es": "Protección contra Eliminación de Instancia SLB Habilitada",
		"fr": "Protection contre la Suppression d'Instance SLB Activée",
		"pt": "Proteção contra Exclusão de Instância SLB Habilitada"
	},
	"description": {
		"en": "Ensures that SLB instances have deletion protection enabled.",
		"zh": "确保 SLB 实例开启了释放保护。",
		"ja": "SLB インスタンスで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass SLB-Instanzen den Löschschutz aktiviert haben.",
		"es": "Garantiza que las instancias SLB tengan protección contra eliminación habilitada.",
		"fr": "Garantit que les instances SLB ont la protection contre la suppression activée.",
		"pt": "Garante que as instâncias SLB tenham proteção contra exclusão habilitada."
	},
	"reason": {
		"en": "If deletion protection is not enabled, the SLB instance may be released accidentally, causing service interruption.",
		"zh": "如果未开启释放保护，SLB 实例可能会被意外释放，导致业务中断。",
		"ja": "削除保護が有効になっていない場合、SLB インスタンスが誤って解放され、サービス中断が発生する可能性があります。",
		"de": "Wenn der Löschschutz nicht aktiviert ist, kann die SLB-Instanz versehentlich freigegeben werden, was zu Dienstunterbrechungen führt.",
		"es": "Si la protección contra eliminación no está habilitada, la instancia SLB puede ser liberada accidentalmente, causando interrupción del servicio.",
		"fr": "Si la protection contre la suppression n'est pas activée, l'instance SLB peut être libérée accidentellement, provoquant une interruption de service.",
		"pt": "Se a proteção contra exclusão não estiver habilitada, a instância SLB pode ser liberada acidentalmente, causando interrupção do serviço."
	},
	"recommendation": {
		"en": "Set delete_protection to 'on' for the SLB instance.",
		"zh": "为 SLB 实例将 delete_protection 设置为 'on'。",
		"ja": "SLB インスタンスの delete_protection を 'on' に設定します。",
		"de": "Setzen Sie delete_protection für die SLB-Instanz auf 'on'.",
		"es": "Establezca delete_protection en 'on' para la instancia SLB.",
		"fr": "Définissez delete_protection sur 'on' pour l'instance SLB.",
		"pt": "Defina delete_protection como 'on' para a instância SLB."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

is_delete_protected(resource) if {
	tf.get_attribute(resource, "delete_protection", "off") == "on"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	not is_delete_protected(resource)
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
