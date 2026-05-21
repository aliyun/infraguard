package infraguard.rules.terraform.slb_all_listener_health_check_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-all-listener-health-check-enabled",
	"severity": "medium",
	"name": {
		"en": "SLB All Listeners Health Check Enabled",
		"zh": "SLB 所有监听开启健康检查",
		"ja": "SLB すべてのリスナーでヘルスチェックが有効",
		"de": "SLB Alle Listener Gesundheitsprüfung aktiviert",
		"es": "Verificación de Salud de Todos los Listeners SLB Habilitada",
		"fr": "Vérification de Santé de Tous les Listeners SLB Activée",
		"pt": "Verificação de Saúde de Todos os Listeners SLB Habilitada"
	},
	"description": {
		"en": "Ensures all SLB listeners have health checks enabled.",
		"zh": "确保所有 SLB 监听均开启了健康检查。",
		"ja": "すべての SLB リスナーでヘルスチェックが有効になっていることを確認します。",
		"de": "Stellt sicher, dass alle SLB-Listener Gesundheitsprüfungen aktiviert haben.",
		"es": "Garantiza que todos los listeners SLB tengan verificaciones de salud habilitadas.",
		"fr": "Garantit que tous les listeners SLB ont les vérifications de santé activées.",
		"pt": "Garante que todos os listeners SLB tenham verificações de saúde habilitadas."
	},
	"reason": {
		"en": "Health checks ensure that traffic is only sent to healthy backend instances.",
		"zh": "健康检查确保流量仅发送到健康的后端实例。",
		"ja": "ヘルスチェックにより、トラフィックが正常なバックエンドインスタンスにのみ送信されることが保証されます。",
		"de": "Gesundheitsprüfungen stellen sicher, dass Datenverkehr nur an gesunde Backend-Instanzen gesendet wird.",
		"es": "Las verificaciones de salud garantizan que el tráfico solo se envíe a instancias backend saludables.",
		"fr": "Les vérifications de santé garantissent que le trafic n'est envoyé qu'aux instances backend saines.",
		"pt": "As verificações de saúde garantem que o tráfego seja enviado apenas para instâncias backend saudáveis."
	},
	"recommendation": {
		"en": "Set health_check to 'on' for all SLB listeners.",
		"zh": "为所有 SLB 监听将 health_check 设置为 'on'。",
		"ja": "すべての SLB リスナーの health_check を 'on' に設定します。",
		"de": "Setzen Sie health_check für alle SLB-Listener auf 'on'.",
		"es": "Establezca health_check en 'on' para todos los listeners SLB.",
		"fr": "Définissez health_check sur 'on' pour tous les listeners SLB.",
		"pt": "Defina health_check como 'on' para todos os listeners SLB."
	},
	"resource_types": ["alicloud_slb_listener"],
	"iac_type": "terraform"
}

is_health_check_enabled(resource) if {
	tf.get_attribute(resource, "health_check", "off") == "on"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_listener")
	not is_health_check_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_listener.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
