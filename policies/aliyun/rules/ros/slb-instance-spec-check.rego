package infraguard.rules.aliyun.slb_instance_spec_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-instance-spec-check",
	"severity": "medium",
	"name": {
		"en": "SLB Instance Specification Check",
		"zh": "SLB 实例规格满足要求",
		"ja": "SLB インスタンス仕様チェック",
		"de": "SLB-Instanz-Spezifikationsprüfung",
		"es": "Verificación de Especificación de Instancia SLB",
		"fr": "Vérification de Spécification d'Instance SLB",
		"pt": "Verificação de Especificação de Instância SLB"
	},
	"description": {
		"en": "SLB instance specifications should meet the required performance criteria based on the specified list.",
		"zh": "SLB 实例规格在指定的规格列表中，视为合规。",
		"ja": "SLB インスタンス仕様は、指定されたリストに基づいて必要なパフォーマンス基準を満たす必要があります。",
		"de": "SLB-Instanz-Spezifikationen sollten die erforderlichen Leistungskriterien basierend auf der angegebenen Liste erfüllen.",
		"es": "Las especificaciones de instancia SLB deben cumplir con los criterios de rendimiento requeridos según la lista especificada.",
		"fr": "Les spécifications d'instance SLB doivent répondre aux critères de performance requis basés sur la liste spécifiée.",
		"pt": "As especificações da instância SLB devem atender aos critérios de desempenho necessários com base na lista especificada."
	},
	"reason": {
		"en": "Using low-specification SLB instances may not meet performance requirements and could lead to bottlenecks.",
		"zh": "使用低规格 SLB 实例可能无法满足性能要求，可能导致瓶颈。",
		"ja": "低仕様の SLB インスタンスを使用すると、パフォーマンス要件を満たさない可能性があり、ボトルネックが発生する可能性があります。",
		"de": "Die Verwendung von SLB-Instanzen mit niedriger Spezifikation erfüllt möglicherweise nicht die Leistungsanforderungen und kann zu Engpässen führen.",
		"es": "Usar instancias SLB de baja especificación puede no cumplir con los requisitos de rendimiento y podría llevar a cuellos de botella.",
		"fr": "L'utilisation d'instances SLB de faible spécification peut ne pas répondre aux exigences de performance et pourrait entraîner des goulots d'étranglement.",
		"pt": "Usar instâncias SLB de baixa especificação pode não atender aos requisitos de desempenho e pode levar a gargalos."
	},
	"recommendation": {
		"en": "Use SLB instances with specifications that meet your performance requirements.",
		"zh": "使用满足性能要求的 SLB 实例规格。",
		"ja": "パフォーマンス要件を満たす仕様の SLB インスタンスを使用します。",
		"de": "Verwenden Sie SLB-Instanzen mit Spezifikationen, die Ihre Leistungsanforderungen erfüllen.",
		"es": "Use instancias SLB con especificaciones que cumplan con sus requisitos de rendimiento.",
		"fr": "Utilisez des instances SLB avec des spécifications qui répondent à vos exigences de performance.",
		"pt": "Use instâncias SLB com especificações que atendam aos seus requisitos de desempenho."
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"]
}

# Allowed specifications (example)
allowed_specs := {
	"slb.s3.small",
	"slb.s3.medium",
	"slb.s3.large",
	"slb.s3.xlarge",
	"slb.s3.xxlarge",
}

is_valid_spec(resource) if {
	spec := helpers.get_property(resource, "LoadBalancerSpec", "")
	spec == ""
}

is_valid_spec(resource) if {
	spec := helpers.get_property(resource, "LoadBalancerSpec", "")
	spec in allowed_specs
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_valid_spec(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoadBalancerSpec"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
