package infraguard.rules.terraform.slb_instance_spec_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Set load_balancer_spec to a specification that meets your performance requirements (e.g., slb.s3.small or higher).",
		"zh": "将 load_balancer_spec 设置为满足性能要求的规格（如 slb.s3.small 或更高）。",
		"ja": "load_balancer_spec をパフォーマンス要件を満たす仕様（例：slb.s3.small 以上）に設定します。",
		"de": "Setzen Sie load_balancer_spec auf eine Spezifikation, die Ihre Leistungsanforderungen erfüllt (z. B. slb.s3.small oder höher).",
		"es": "Establezca load_balancer_spec en una especificación que cumpla con sus requisitos de rendimiento (por ejemplo, slb.s3.small o superior).",
		"fr": "Définissez load_balancer_spec sur une spécification qui répond à vos exigences de performance (par exemple, slb.s3.small ou supérieur).",
		"pt": "Defina load_balancer_spec para uma especificação que atenda aos seus requisitos de desempenho (por exemplo, slb.s3.small ou superior)."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

allowed_specs := {
	"slb.s3.small",
	"slb.s3.medium",
	"slb.s3.large",
	"slb.s3.xlarge",
	"slb.s3.xxlarge",
}

is_valid_spec(resource) if {
	spec := tf.get_attribute(resource, "load_balancer_spec", "")
	spec == ""
}

is_valid_spec(resource) if {
	spec := tf.get_attribute(resource, "load_balancer_spec", "")
	not tf.is_unknown(spec)
	spec in allowed_specs
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	not is_valid_spec(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_load_balancer.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
