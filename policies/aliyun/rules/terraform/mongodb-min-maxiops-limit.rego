package infraguard.rules.terraform.mongodb_min_maxiops_limit

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-min-maxiops-limit",
	"severity": "high",
	"name": {
		"en": "MongoDB Instance Minimum IOPS Storage",
		"zh": "MongoDB 实例最小 IOPS 存储检查",
		"ja": "MongoDB が最小 IOPS 要件を満たしている",
		"de": "MongoDB erfüllt Mindest-IOPS-Anforderungen",
		"es": "MongoDB Cumple con los Requisitos Mínimos de IOPS",
		"fr": "MongoDB Répond aux Exigences Minimales d'IOPS",
		"pt": "MongoDB Atende aos Requisitos Mínimos de IOPS"
	},
	"description": {
		"en": "MongoDB instance storage should be at least 20 GB to meet IOPS requirements.",
		"zh": "MongoDB 实例存储应至少为 20 GB 以满足 IOPS 要求。",
		"ja": "MongoDB インスタンスが少なくとも最小要件 IOPS を提供していることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen mindestens die erforderliche Mindest-IOPS bereitstellen.",
		"es": "Garantiza que las instancias MongoDB proporcionen al menos el IOPS mínimo requerido.",
		"fr": "Garantit que les instances MongoDB fournissent au moins l'IOPS minimum requis.",
		"pt": "Garante que as instâncias MongoDB forneçam pelo menos o IOPS mínimo necessário."
	},
	"reason": {
		"en": "The MongoDB instance storage is below the minimum threshold for adequate IOPS.",
		"zh": "MongoDB 实例存储低于满足 IOPS 要求的最小阈值。",
		"ja": "IOPS が不足すると、負荷下でパフォーマンスの問題が発生する可能性があります。",
		"de": "Unzureichende IOPS können bei Last zu Leistungsproblemen führen.",
		"es": "IOPS insuficientes pueden causar problemas de rendimiento bajo carga.",
		"fr": "Des IOPS insuffisantes peuvent causer des problèmes de performance sous charge.",
		"pt": "IOPS insuficientes podem causar problemas de desempenho sob carga."
	},
	"recommendation": {
		"en": "Set db_instance_storage to at least 20 GB.",
		"zh": "将 db_instance_storage 设置为至少 20 GB。",
		"ja": "十分な IOPS を提供するインスタンスクラスまたはストレージを選択します。",
		"de": "Wählen Sie eine Instanzklasse oder Speicher, die ausreichend IOPS bereitstellt.",
		"es": "Seleccione una clase de instancia o almacenamiento que proporcione IOPS suficientes.",
		"fr": "Sélectionnez une classe d'instance ou un stockage qui fournit des IOPS suffisants.",
		"pt": "Selecione uma classe de instância ou armazenamento que forneça IOPS suficientes."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	storage := tf.get_attribute(resource, "db_instance_storage", 0)
	storage < 20
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
