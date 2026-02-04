package infraguard.rules.aliyun.fc_service_log_enable

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "fc-service-log-enable",
	"name": {
		"en": "FC Service Log Enable",
		"zh": "函数计算服务启用日志功能",
		"ja": "FC サービスログが有効",
		"de": "FC-Service Protokoll aktivieren",
		"es": "Habilitar Registro del Servicio FC",
		"fr": "Activer le Journal du Service FC",
		"pt": "Habilitar Log do Serviço FC",
	},
	"severity": "medium",
	"description": {
		"en": "FC services should have logging enabled for monitoring and troubleshooting.",
		"zh": "函数计算服务启用日志功能，视为合规。",
		"ja": "FC サービスは監視とトラブルシューティングのためにログ記録を有効にする必要があります。",
		"de": "FC-Services sollten Protokollierung für Überwachung und Fehlerbehebung aktiviert haben.",
		"es": "Los servicios FC deben tener registro habilitado para monitoreo y solución de problemas.",
		"fr": "Les services FC doivent avoir la journalisation activée pour la surveillance et le dépannage.",
		"pt": "Os serviços FC devem ter registro habilitado para monitoramento e solução de problemas.",
	},
	"reason": {
		"en": "The FC service does not have logging enabled, which may affect troubleshooting and auditing.",
		"zh": "函数计算服务未启用日志功能，可能影响问题排查和审计。",
		"ja": "FC サービスでログ記録が有効になっていないため、トラブルシューティングと監査に影響を与える可能性があります。",
		"de": "Der FC-Service hat keine Protokollierung aktiviert, was die Fehlerbehebung und Prüfung beeinträchtigen kann.",
		"es": "El servicio FC no tiene registro habilitado, lo que puede afectar la solución de problemas y la auditoría.",
		"fr": "Le service FC n'a pas la journalisation activée, ce qui peut affecter le dépannage et l'audit.",
		"pt": "O serviço FC não tem registro habilitado, o que pode afetar a solução de problemas e a auditoria.",
	},
	"recommendation": {
		"en": "Enable logging for the FC service by configuring LogConfig with Logstore and Project.",
		"zh": "通过配置 LogConfig（包含 Logstore 和 Project）为函数计算服务启用日志。",
		"ja": "Logstore と Project で LogConfig を設定して、FC サービスのログ記録を有効にします。",
		"de": "Aktivieren Sie die Protokollierung für den FC-Service, indem Sie LogConfig mit Logstore und Project konfigurieren.",
		"es": "Habilite el registro para el servicio FC configurando LogConfig con Logstore y Project.",
		"fr": "Activez la journalisation pour le service FC en configurant LogConfig avec Logstore et Project.",
		"pt": "Habilite o registro para o serviço FC configurando LogConfig com Logstore e Project.",
	},
	"resource_types": ["ALIYUN::FC::Service"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Service")
	log_config := helpers.get_property(resource, "LogConfig", {})
	log_config == {}
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LogConfig"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
