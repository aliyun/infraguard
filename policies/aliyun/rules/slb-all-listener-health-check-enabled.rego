package infraguard.rules.aliyun.slb_all_listener_health_check_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listener-health-check-enabled",
	"severity": "high",
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
		"en": "Enable health checks for all SLB listeners.",
		"zh": "为所有 SLB 监听开启健康检查。",
		"ja": "すべての SLB リスナーでヘルスチェックを有効にします。",
		"de": "Aktivieren Sie Gesundheitsprüfungen für alle SLB-Listener.",
		"es": "Habilite verificaciones de salud para todos los listeners SLB.",
		"fr": "Activez les vérifications de santé pour tous les listeners SLB.",
		"pt": "Habilite verificações de saúde para todos os listeners SLB."
	},
	"resource_types": ["ALIYUN::SLB::Listener"]
}

is_compliant(resource) if {
	# HealthCheck is a map with Switch property
	hc := helpers.get_property(resource, "HealthCheck", {})
	switch_val := object.get(hc, "Switch", "off")
	switch_val == "on"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HealthCheck"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
