package infraguard.rules.terraform.elasticsearch_instance_node_not_use_specified_spec

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "elasticsearch-instance-node-not-use-specified-spec",
	"severity": "high",
	"name": {"en": "Elasticsearch Instance Does Not Use Deprecated Spec", "zh": "未使用不推荐的 Elasticsearch 实例", "ja": "Elasticsearch インスタンスが非推奨仕様を使用していない", "de": "Elasticsearch-Instanz verwendet keine veraltete Spezifikation", "es": "La Instancia Elasticsearch No Usa Especificación Deprecada", "fr": "L'Instance Elasticsearch N'utilise Pas de Spécification Dépréciée", "pt": "A Instância Elasticsearch Não Usa Especificação Depreciada"},
	"description": {"en": "Ensures that Elasticsearch instances do not use deprecated or unsupported node specifications.", "zh": "未使用参数指定的 Elasticsearch 规格实例，视为合规。", "ja": "Elasticsearch インスタンスが非推奨またはサポートされていないノード仕様を使用していないことを確認します。", "de": "Stellt sicher, dass Elasticsearch-Instanzen keine veralteten oder nicht unterstützten Knotenspezifikationen verwenden.", "es": "Garantiza que las instancias Elasticsearch no usen especificaciones de nodo deprecadas o no compatibles.", "fr": "Garantit que les instances Elasticsearch n'utilisent pas de spécifications de nœud dépréciées ou non prises en charge.", "pt": "Garante que as instâncias Elasticsearch não usem especificações de nó depreciadas ou não suportadas."},
	"reason": {"en": "Using deprecated Elasticsearch node specifications may lack support and security updates.", "zh": "使用不推荐的 Elasticsearch 规格实例，可能缺少支持和安全更新。", "ja": "非推奨の Elasticsearch ノード仕様を使用すると、サポートとセキュリティ更新が不足する可能性があります。", "de": "Die Verwendung veralteter Elasticsearch-Knotenspezifikationen kann zu fehlender Unterstützung und Sicherheitsupdates führen.", "es": "Usar especificaciones de nodo Elasticsearch deprecadas puede carecer de soporte y actualizaciones de seguridad.", "fr": "L'utilisation de spécifications de nœud Elasticsearch dépréciées peut manquer de support et de mises à jour de sécurité.", "pt": "Usar especificações de nó Elasticsearch depreciadas pode faltar suporte e atualizações de segurança."},
	"recommendation": {"en": "Upgrade to a supported Elasticsearch node specification.", "zh": "请升级到支持的 Elasticsearch 节点规格。", "ja": "サポートされている Elasticsearch ノード仕様にアップグレードします。", "de": "Aktualisieren Sie auf eine unterstützte Elasticsearch-Knotenspezifikation.", "es": "Actualice a una especificación de nodo Elasticsearch compatible.", "fr": "Mettez à niveau vers une spécification de nœud Elasticsearch prise en charge.", "pt": "Atualize para uma especificação de nó Elasticsearch suportada."},
	"resource_types": ["alicloud_elasticsearch_instance"],
	"iac_type": "terraform"
}

default_deprecated_specs := ["elasticsearch.sn1.small", "elasticsearch.sn2.small", "elasticsearch.mn1.small"]

deprecated_specs := specs if {
	params := object.get(input, "rule_parameters", {})
	specs := object.get(params, "deprecated_node_specs", default_deprecated_specs)
	specs != ""
} else := default_deprecated_specs

is_deprecated_spec(node_spec) if {
	some deprecated in deprecated_specs
	contains(node_spec, deprecated)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_elasticsearch_instance")
	data_node := tf.get_attribute(resource, "data_node", {})
	not tf.is_unknown(data_node)
	node_spec := data_node.spec
	is_deprecated_spec(node_spec)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_elasticsearch_instance.%s", [name]),
		"violation_path": ["data_node", "spec"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
