package infraguard.rules.aliyun.mongodb_min_maxiops_limit

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-min-maxiops-limit",
	"severity": "high",
	"name": {
		"en": "MongoDB Meets Minimum IOPS Requirements",
		"zh": "MongoDB 实例满足指定读写次数要求",
		"ja": "MongoDB が最小 IOPS 要件を満たしている",
		"de": "MongoDB erfüllt Mindest-IOPS-Anforderungen",
		"es": "MongoDB Cumple con los Requisitos Mínimos de IOPS",
		"fr": "MongoDB Répond aux Exigences Minimales d'IOPS",
		"pt": "MongoDB Atende aos Requisitos Mínimos de IOPS"
	},
	"description": {
		"en": "Ensures MongoDB instances provide at least the minimum required IOPS.",
		"zh": "确保 MongoDB 实例提供至少所需的最少 IOPS。",
		"ja": "MongoDB インスタンスが少なくとも最小要件 IOPS を提供していることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen mindestens die erforderliche Mindest-IOPS bereitstellen.",
		"es": "Garantiza que las instancias MongoDB proporcionen al menos el IOPS mínimo requerido.",
		"fr": "Garantit que les instances MongoDB fournissent au moins l'IOPS minimum requis.",
		"pt": "Garante que as instâncias MongoDB forneçam pelo menos o IOPS mínimo necessário."
	},
	"reason": {
		"en": "Insufficient IOPS may cause performance issues under load.",
		"zh": "IOPS 不足可能在负载下导致性能问题。",
		"ja": "IOPS が不足すると、負荷下でパフォーマンスの問題が発生する可能性があります。",
		"de": "Unzureichende IOPS können bei Last zu Leistungsproblemen führen.",
		"es": "IOPS insuficientes pueden causar problemas de rendimiento bajo carga.",
		"fr": "Des IOPS insuffisantes peuvent causer des problèmes de performance sous charge.",
		"pt": "IOPS insuficientes podem causar problemas de desempenho sob carga."
	},
	"recommendation": {
		"en": "Select an instance class or storage that provides sufficient IOPS.",
		"zh": "选择提供足够 IOPS 的实例规格或存储。",
		"ja": "十分な IOPS を提供するインスタンスクラスまたはストレージを選択します。",
		"de": "Wählen Sie eine Instanzklasse oder Speicher, die ausreichend IOPS bereitstellt.",
		"es": "Seleccione una clase de instancia o almacenamiento que proporcione IOPS suficientes.",
		"fr": "Sélectionnez une classe d'instance ou un stockage qui fournit des IOPS suffisants.",
		"pt": "Selecione uma classe de instância ou armazenamento que forneça IOPS suficientes."
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"]
}

# Default minimum IOPS
default_min_iops := 1000

# Get min IOPS from parameter or use default
get_min_iops := iops if {
	iops := input.parameters.minIOPS
	is_number(iops)
} else := default_min_iops

# Get max IOPS for the instance
get_max_iops(resource) := iops if {
	iops := helpers.get_property(resource, "MaxIOPS", 0)
	is_number(iops)
}

# Check if instance meets IOPS requirements
is_compliant(resource) if {
	max_iops := get_max_iops(resource)
	min_required := get_min_iops()
	max_iops >= min_required
}

# Also check based on instance class and storage
is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")
	instance_storage := helpers.get_property(resource, "DBInstanceStorage", 0)
	storage_type := helpers.get_property(resource, "StorageType", "cloud_ssd")

	instance_storage >= 100
	contains(lower(storage_type), "ssd")
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MaxIOPS"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
