package infraguard.rules.aliyun.elasticsearch_instance_node_not_use_specified_spec

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "elasticsearch-instance-node-not-use-specified-spec",
	"name": {
		"en": "Elasticsearch Instance Does Not Use Deprecated Spec",
		"zh": "未使用不推荐的 Elasticsearch 实例",
		"ja": "Elasticsearch インスタンスが非推奨仕様を使用していない",
		"de": "Elasticsearch-Instanz verwendet keine veraltete Spezifikation",
		"es": "La Instancia Elasticsearch No Usa Especificación Deprecada",
		"fr": "L'Instance Elasticsearch N'utilise Pas de Spécification Dépréciée",
		"pt": "A Instância Elasticsearch Não Usa Especificação Depreciada",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Elasticsearch instances do not use deprecated or unsupported node specifications.",
		"zh": "未使用参数指定的 Elasticsearch 规格实例，视为合规。",
		"ja": "Elasticsearch インスタンスが非推奨またはサポートされていないノード仕様を使用していないことを確認します。",
		"de": "Stellt sicher, dass Elasticsearch-Instanzen keine veralteten oder nicht unterstützten Knotenspezifikationen verwenden.",
		"es": "Garantiza que las instancias Elasticsearch no usen especificaciones de nodo deprecadas o no compatibles.",
		"fr": "Garantit que les instances Elasticsearch n'utilisent pas de spécifications de nœud dépréciées ou non prises en charge.",
		"pt": "Garante que as instâncias Elasticsearch não usem especificações de nó depreciadas ou não suportadas.",
	},
	"reason": {
		"en": "Using deprecated Elasticsearch node specifications may lack support and security updates.",
		"zh": "使用不推荐的 Elasticsearch 规格实例，可能缺少支持和安全更新。",
		"ja": "非推奨の Elasticsearch ノード仕様を使用すると、サポートとセキュリティ更新が不足する可能性があります。",
		"de": "Die Verwendung veralteter Elasticsearch-Knotenspezifikationen kann zu fehlender Unterstützung und Sicherheitsupdates führen.",
		"es": "Usar especificaciones de nodo Elasticsearch deprecadas puede carecer de soporte y actualizaciones de seguridad.",
		"fr": "L'utilisation de spécifications de nœud Elasticsearch dépréciées peut manquer de support et de mises à jour de sécurité.",
		"pt": "Usar especificações de nó Elasticsearch depreciadas pode faltar suporte e atualizações de segurança.",
	},
	"recommendation": {
		"en": "Upgrade to a supported Elasticsearch node specification.",
		"zh": "请升级到支持的 Elasticsearch 节点规格。",
		"ja": "サポートされている Elasticsearch ノード仕様にアップグレードします。",
		"de": "Aktualisieren Sie auf eine unterstützte Elasticsearch-Knotenspezifikation.",
		"es": "Actualice a una especificación de nodo Elasticsearch compatible.",
		"fr": "Mettez à niveau vers une spécification de nœud Elasticsearch prise en charge.",
		"pt": "Atualize para uma especificação de nó Elasticsearch suportada.",
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

# Default deprecated specs (should be parameterized in production)
deprecated_specs := [
	"elasticsearch.sn1.small",
	"elasticsearch.sn2.small",
	"elasticsearch.mn1.small",
]

# Check if rule parameters exist
has_rule_parameters := count(input.rule_parameters) > 0

# Get deprecated specs from parameters or use default
deprecated_list := deprecated_specs if {
	not has_rule_parameters
}

deprecated_list := deprecated_specs if {
	has_rule_parameters
	input.rule_parameters.deprecated_node_specs == ""
}

deprecated_list := deprecated_specs if {
	has_rule_parameters
	not input.rule_parameters.deprecated_node_specs
}

deprecated_list := input.rule_parameters.deprecated_node_specs if {
	has_rule_parameters
	input.rule_parameters.deprecated_node_specs != ""
}

# Check if a node spec is deprecated
is_deprecated_spec(node_spec) if {
	some deprecated in deprecated_list
	contains(node_spec, deprecated)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")

	data_node := resource.Properties.DataNode
	node_spec := data_node.Spec

	is_deprecated_spec(node_spec)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DataNode", "Spec"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
