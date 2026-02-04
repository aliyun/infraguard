package infraguard.rules.aliyun.redis_instance_double_node_type

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-instance-double-node-type",
	"name": {
		"en": "Redis Instance Double Node Type",
		"zh": "Redis 实例节点类型为双副本",
		"ja": "Redis インスタンスダブルノードタイプ",
		"de": "Redis-Instanz Doppelknotentyp",
		"es": "Tipo de Nodo Doble de Instancia Redis",
		"fr": "Type de Nœud Double d'Instance Redis",
		"pt": "Tipo de Nó Duplo de Instância Redis",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Redis instance uses double node type for high availability.",
		"zh": "确保 Redis 实例使用双副本节点类型以确保高可用性。",
		"ja": "Redis インスタンスが高可用性のためにダブルノードタイプを使用していることを確認します。",
		"de": "Stellt sicher, dass Redis-Instanz den Doppelknotentyp für Hochverfügbarkeit verwendet.",
		"es": "Garantiza que la instancia Redis use tipo de nodo doble para alta disponibilidad.",
		"fr": "Garantit que l'instance Redis utilise le type de nœud double pour une haute disponibilité.",
		"pt": "Garante que a instância Redis use tipo de nó duplo para alta disponibilidade.",
	},
	"reason": {
		"en": "Double node type provides high availability through replication.",
		"zh": "双副本类型通过复制提供高可用性。",
		"ja": "ダブルノードタイプは、レプリケーションを通じて高可用性を提供します。",
		"de": "Doppelknotentyp bietet Hochverfügbarkeit durch Replikation.",
		"es": "El tipo de nodo doble proporciona alta disponibilidad mediante replicación.",
		"fr": "Le type de nœud double fournit une haute disponibilité grâce à la réplication.",
		"pt": "O tipo de nó duplo fornece alta disponibilidade através de replicação.",
	},
	"recommendation": {
		"en": "Use double node type for Redis instance.",
		"zh": "为 Redis 实例使用双副本节点类型。",
		"ja": "Redis インスタンスにダブルノードタイプを使用します。",
		"de": "Verwenden Sie den Doppelknotentyp für Redis-Instanz.",
		"es": "Use tipo de nodo doble para la instancia Redis.",
		"fr": "Utilisez le type de nœud double pour l'instance Redis.",
		"pt": "Use tipo de nó duplo para a instância Redis.",
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	node_type := helpers.get_property(resource, "NodeType", "Double")
	node_type == "Double"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NodeType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
