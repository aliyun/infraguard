package infraguard.rules.terraform.slb_instance_loadbalancerspec_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-instance-loadbalancerspec-check",
	"severity": "low",
	"name": {
		"en": "SLB Instance Spec Check",
		"zh": "SLB 规格合规性检查",
		"ja": "SLB インスタンス仕様チェック",
		"de": "SLB-Instanz Spezifikationsprüfung",
		"es": "Verificación de Especificación de Instancia SLB",
		"fr": "Vérification de Spécification d'Instance SLB",
		"pt": "Verificação de Especificação de Instância SLB"
	},
	"description": {
		"en": "Ensures SLB instances use approved performance specifications.",
		"zh": "确保 SLB 实例使用批准的性能规格。",
		"ja": "SLB インスタンスが承認されたパフォーマンス仕様を使用していることを確認します。",
		"de": "Stellt sicher, dass SLB-Instanzen genehmigte Leistungsspezifikationen verwenden.",
		"es": "Garantiza que las instancias SLB usen especificaciones de rendimiento aprobadas.",
		"fr": "Garantit que les instances SLB utilisent des spécifications de performance approuvées.",
		"pt": "Garante que as instâncias SLB usem especificações de desempenho aprovadas."
	},
	"reason": {
		"en": "Using specific specs helps in cost management and performance standardization.",
		"zh": "使用特定规格有助于成本管理和性能标准化。",
		"ja": "特定の仕様を使用することで、コスト管理とパフォーマンスの標準化に役立ちます。",
		"de": "Die Verwendung spezifischer Spezifikationen hilft bei der Kostenverwaltung und Leistungsstandardisierung.",
		"es": "Usar especificaciones específicas ayuda en la gestión de costos y la estandarización del rendimiento.",
		"fr": "L'utilisation de spécifications spécifiques aide à la gestion des coûts et à la standardisation des performances.",
		"pt": "Usar especificações específicas ajuda no gerenciamento de custos e padronização de desempenho."
	},
	"recommendation": {
		"en": "Set load_balancer_spec to a value from the approved list (e.g., slb.s1.small).",
		"zh": "将 load_balancer_spec 设置为批准列表中的规格（如 slb.s1.small）。",
		"ja": "load_balancer_spec を承認リストの仕様（例：slb.s1.small）に設定します。",
		"de": "Setzen Sie load_balancer_spec auf einen Wert aus der genehmigten Liste (z. B. slb.s1.small).",
		"es": "Establezca load_balancer_spec en un valor de la lista aprobada (por ejemplo, slb.s1.small).",
		"fr": "Définissez load_balancer_spec sur une valeur de la liste approuvée (par exemple, slb.s1.small).",
		"pt": "Defina load_balancer_spec para um valor da lista aprovada (por exemplo, slb.s1.small)."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

allowed_specs := ["slb.s1.small", "slb.s2.small", "slb.s3.small"]

is_compliant(resource) if {
	spec := tf.get_attribute(resource, "load_balancer_spec", "")
	not tf.is_unknown(spec)
	spec in allowed_specs
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_load_balancer.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
