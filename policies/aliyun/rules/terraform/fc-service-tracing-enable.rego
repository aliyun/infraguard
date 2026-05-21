package infraguard.rules.terraform.fc_service_tracing_enable

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "fc-service-tracing-enable",
	"severity": "medium",
	"name": {
		"en": "FC Service Tracing Enable",
		"zh": "函数计算服务启用链路追踪",
		"ja": "FC サービストレーシング有効",
		"de": "FC-Service Tracing aktivieren",
		"es": "Habilitar Seguimiento de Servicio FC",
		"fr": "Activer le Traçage de Service FC",
		"pt": "Habilitar Rastreamento de Serviço FC"
	},
	"description": {
		"en": "FC services should have tracing enabled for performance monitoring and debugging.",
		"zh": "函数计算服务启用链路追踪功能，视为合规。",
		"ja": "FC サービスは、パフォーマンス監視とデバッグのためにトレーシングを有効にする必要があります。",
		"de": "FC-Services sollten Tracing für Leistungsüberwachung und Debugging aktiviert haben.",
		"es": "Los servicios FC deben tener seguimiento habilitado para monitoreo de rendimiento y depuración.",
		"fr": "Les services FC doivent avoir le traçage activé pour la surveillance des performances et le débogage.",
		"pt": "Os serviços FC devem ter rastreamento habilitado para monitoramento de desempenho e depuração."
	},
	"reason": {
		"en": "The FC service does not have tracing enabled, which may affect performance analysis.",
		"zh": "函数计算服务未启用链路追踪，可能影响性能分析和问题排查。",
		"ja": "FC サービスでトレーシングが有効になっていないため、パフォーマンス分析に影響を与える可能性があります。",
		"de": "Der FC-Service hat kein Tracing aktiviert, was die Leistungsanalyse beeinträchtigen kann.",
		"es": "El servicio FC no tiene seguimiento habilitado, lo que puede afectar el análisis de rendimiento.",
		"fr": "Le service FC n'a pas le traçage activé, ce qui peut affecter l'analyse des performances.",
		"pt": "O serviço FC não tem rastreamento habilitado, o que pode afetar a análise de desempenho."
	},
	"recommendation": {
		"en": "Enable tracing for the FC service by configuring the tracing_config block.",
		"zh": "通过配置 tracing_config 块为函数计算服务启用链路追踪。",
		"ja": "TracingConfig を設定して FC サービスのトレーシングを有効にします。",
		"de": "Aktivieren Sie Tracing für den FC-Service durch Konfiguration von TracingConfig.",
		"es": "Habilite el seguimiento para el servicio FC configurando TracingConfig.",
		"fr": "Activez le traçage pour le service FC en configurant TracingConfig.",
		"pt": "Habilite o rastreamento para o serviço FC configurando TracingConfig."
	},
	"resource_types": ["alicloud_fc_service"],
	"iac_type": "terraform"
}

has_tracing_config(resource) if {
	tracing_config := tf.get_attribute(resource, "tracing_config", {})
	not tf.is_unknown(tracing_config)
	tracing_config != {}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_fc_service")
	not has_tracing_config(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_fc_service.%s", [name]),
		"violation_path": ["tracing_config"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
