package infraguard.rules.aliyun.mongodb_min_maxconnections_limit

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-min-maxconnections-limit",
	"severity": "high",
	"name": {
		"en": "MongoDB Meets Minimum Connection Requirements",
		"zh": "MongoDB 满足指定连接数要求",
		"ja": "MongoDB が最小接続要件を満たしている",
		"de": "MongoDB erfüllt Mindestverbindungsanforderungen",
		"es": "MongoDB Cumple los Requisitos Mínimos de Conexión",
		"fr": "MongoDB Répond aux Exigences Minimales de Connexion",
		"pt": "MongoDB Atende aos Requisitos Mínimos de Conexão"
	},
	"description": {
		"en": "Ensures MongoDB instances provide at least the minimum required number of connections.",
		"zh": "确保 MongoDB 实例提供至少所需的最少连接数。",
		"ja": "MongoDB インスタンスが少なくとも必要な最小接続数を提供することを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen mindestens die erforderliche Mindestanzahl von Verbindungen bereitstellen.",
		"es": "Garantiza que las instancias MongoDB proporcionen al menos el número mínimo requerido de conexiones.",
		"fr": "Garantit que les instances MongoDB fournissent au moins le nombre minimum requis de connexions.",
		"pt": "Garante que as instâncias MongoDB forneçam pelo menos o número mínimo necessário de conexões."
	},
	"reason": {
		"en": "Insufficient connection limits may cause application failures when under load.",
		"zh": "连接数不足可能在负载下导致应用程序故障。",
		"ja": "接続制限が不十分な場合、負荷下でアプリケーション障害が発生する可能性があります。",
		"de": "Unzureichende Verbindungslimits können bei Belastung zu Anwendungsfehlern führen.",
		"es": "Los límites de conexión insuficientes pueden causar fallas de aplicación bajo carga.",
		"fr": "Des limites de connexion insuffisantes peuvent provoquer des défaillances d'application sous charge.",
		"pt": "Limites de conexão insuficientes podem causar falhas de aplicação sob carga."
	},
	"recommendation": {
		"en": "Select an instance class that provides sufficient connection limits.",
		"zh": "选择提供足够连接数限制的实例规格。",
		"ja": "十分な接続制限を提供するインスタンスクラスを選択します。",
		"de": "Wählen Sie eine Instanzklasse, die ausreichende Verbindungslimits bietet.",
		"es": "Seleccione una clase de instancia que proporcione límites de conexión suficientes.",
		"fr": "Sélectionnez une classe d'instance qui fournit des limites de connexion suffisantes.",
		"pt": "Selecione uma classe de instância que forneça limites de conexão suficientes."
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"]
}

# Default minimum connections
default_min_connections := 500

# Get min connections from parameter or use default
get_min_connections := num if {
	num := input.parameters.minConnections
	is_number(num)
}

get_min_connections := default_min_connections

# Get max connections for the instance
get_max_connections(resource) := conn if {
	conn := object.get(resource.Properties, "MaxConnections", 0)
	is_number(conn)
}

# Check if instance meets connection requirements
is_compliant(resource) if {
	max_conn := get_max_connections(resource)
	min_required := get_min_connections()
	max_conn >= min_required
}

# Also check based on instance class capability
is_compliant(resource) if {
	instance_class := object.get(resource.Properties, "DBInstanceClass", "")

	# Map instance class to expected max connections (simplified)
	class_conn_map := {
		"dds.mongo.stand-alone": 200,
		"dds.mongo.replica_set": 1000,
		"dds.mongo.sharding": 2000,
	}
	expected_conn := class_conn_map[lower(instance_class)]
	expected_conn != null
	expected_conn >= get_min_connections()
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MaxConnections"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
