package infraguard.rules.aliyun.slb_instance_loadbalancerspec_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-instance-loadbalancerspec-check",
	"name": {
		"en": "SLB Instance Spec Check",
		"zh": "SLB 规格合规性检查",
		"ja": "SLB インスタンス仕様チェック",
		"de": "SLB-Instanz Spezifikationsprüfung",
		"es": "Verificación de Especificación de Instancia SLB",
		"fr": "Vérification de Spécification d'Instance SLB",
		"pt": "Verificação de Especificação de Instância SLB",
	},
	"severity": "low",
	"description": {
		"en": "Ensures SLB instances use approved performance specifications.",
		"zh": "确保 SLB 实例使用批准的性能规格。",
		"ja": "SLB インスタンスが承認されたパフォーマンス仕様を使用していることを確認します。",
		"de": "Stellt sicher, dass SLB-Instanzen genehmigte Leistungsspezifikationen verwenden.",
		"es": "Garantiza que las instancias SLB usen especificaciones de rendimiento aprobadas.",
		"fr": "Garantit que les instances SLB utilisent des spécifications de performance approuvées.",
		"pt": "Garante que as instâncias SLB usem especificações de desempenho aprovadas.",
	},
	"reason": {
		"en": "Using specific specs helps in cost management and performance standardization.",
		"zh": "使用特定规格有助于成本管理和性能标准化。",
		"ja": "特定の仕様を使用することで、コスト管理とパフォーマンスの標準化に役立ちます。",
		"de": "Die Verwendung spezifischer Spezifikationen hilft bei der Kostenverwaltung und Leistungsstandardisierung.",
		"es": "Usar especificaciones específicas ayuda en la gestión de costos y la estandarización del rendimiento.",
		"fr": "L'utilisation de spécifications spécifiques aide à la gestion des coûts et à la standardisation des performances.",
		"pt": "Usar especificações específicas ajuda no gerenciamento de custos e padronização de desempenho.",
	},
	"recommendation": {
		"en": "Use a spec from the approved list (e.g., slb.s1.small).",
		"zh": "使用批准列表中的规格（如 slb.s1.small）。",
		"ja": "承認リストの仕様（例：slb.s1.small）を使用します。",
		"de": "Verwenden Sie eine Spezifikation aus der genehmigten Liste (z. B. slb.s1.small).",
		"es": "Use una especificación de la lista aprobada (por ejemplo, slb.s1.small).",
		"fr": "Utilisez une spécification de la liste approuvée (par exemple, slb.s1.small).",
		"pt": "Use uma especificação da lista aprovada (por exemplo, slb.s1.small).",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

allowed_specs := ["slb.s1.small", "slb.s2.small", "slb.s3.small"]

is_compliant(resource) if {
	spec := helpers.get_property(resource, "LoadBalancerSpec", "")
	helpers.includes(allowed_specs, spec)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoadBalancerSpec"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
