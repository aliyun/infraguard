package infraguard.rules.terraform.mongodb_min_maxconnections_limit

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-min-maxconnections-limit",
	"severity": "high",
	"name": {
		"en": "MongoDB Instance Minimum Connections Spec",
		"zh": "MongoDB 实例最小连接数规格检查",
		"ja": "MongoDB が最小接続要件を満たしている",
		"de": "MongoDB erfüllt Mindestverbindungsanforderungen",
		"es": "MongoDB Cumple los Requisitos Mínimos de Conexión",
		"fr": "MongoDB Répond aux Exigences Minimales de Connexion",
		"pt": "MongoDB Atende aos Requisitos Mínimos de Conexão"
	},
	"description": {
		"en": "MongoDB instance class should meet minimum connection requirements (not use the smallest spec).",
		"zh": "MongoDB 实例规格应满足最小连接数要求（不使用最小规格）。",
		"ja": "MongoDB インスタンスが少なくとも必要な最小接続数を提供することを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen mindestens die erforderliche Mindestanzahl von Verbindungen bereitstellen.",
		"es": "Garantiza que las instancias MongoDB proporcionen al menos el número mínimo requerido de conexiones.",
		"fr": "Garantit que les instances MongoDB fournissent au moins le nombre minimum requis de connexions.",
		"pt": "Garante que as instâncias MongoDB forneçam pelo menos o número mínimo necessário de conexões."
	},
	"reason": {
		"en": "The MongoDB instance is using the smallest instance class which may not support sufficient connections.",
		"zh": "MongoDB 实例使用了最小规格，可能无法支持足够的连接数。",
		"ja": "接続制限が不十分な場合、負荷下でアプリケーション障害が発生する可能性があります。",
		"de": "Unzureichende Verbindungslimits können bei Belastung zu Anwendungsfehlern führen.",
		"es": "Los límites de conexión insuficientes pueden causar fallas de aplicación bajo carga.",
		"fr": "Des limites de connexion insuffisantes peuvent provoquer des défaillances d'application sous charge.",
		"pt": "Limites de conexão insuficientes podem causar falhas de aplicação sob carga."
	},
	"recommendation": {
		"en": "Use at least dds.mongo.standard or higher instance class.",
		"zh": "使用 dds.mongo.standard 或更高的实例规格。",
		"ja": "十分な接続制限を提供するインスタンスクラスを選択します。",
		"de": "Wählen Sie eine Instanzklasse, die ausreichende Verbindungslimits bietet.",
		"es": "Seleccione una clase de instancia que proporcione límites de conexión suficientes.",
		"fr": "Sélectionnez une classe d'instance qui fournit des limites de connexion suffisantes.",
		"pt": "Selecione uma classe de instância que forneça limites de conexão suficientes."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

# List of instance classes that are too small
small_classes := {"dds.mongo.small"}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	db_class := tf.get_attribute(resource, "db_instance_class", "")
	db_class in small_classes
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
