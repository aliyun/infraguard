package infraguard.rules.terraform.redis_instance_double_node_type

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-double-node-type",
	"severity": "medium",
	"name": {
		"en": "Redis Instance Double Node Type",
		"zh": "Redis 实例节点类型为双副本",
		"ja": "Redis インスタンスダブルノードタイプ",
		"de": "Redis-Instanz Doppelknotentyp",
		"es": "Tipo de Nodo Doble de Instancia Redis",
		"fr": "Type de Nœud Double d'Instance Redis",
		"pt": "Tipo de Nó Duplo de Instância Redis"
	},
	"description": {
		"en": "Ensures Redis instance uses double node type for high availability.",
		"zh": "确保 Redis 实例使用双副本节点类型以确保高可用性。",
		"ja": "Redis インスタンスが高可用性のためにダブルノードタイプを使用していることを確認します。",
		"de": "Stellt sicher, dass Redis-Instanz den Doppelknotentyp für Hochverfügbarkeit verwendet.",
		"es": "Garantiza que la instancia Redis use tipo de nodo doble para alta disponibilidad.",
		"fr": "Garantit que l'instance Redis utilise le type de nœud double pour une haute disponibilité.",
		"pt": "Garante que a instância Redis use tipo de nó duplo para alta disponibilidade."
	},
	"reason": {
		"en": "Double node type provides high availability through replication.",
		"zh": "双副本类型通过复制提供高可用性。",
		"ja": "ダブルノードタイプは、レプリケーションを通じて高可用性を提供します。",
		"de": "Doppelknotentyp bietet Hochverfügbarkeit durch Replikation.",
		"es": "El tipo de nodo doble proporciona alta disponibilidad mediante replicación.",
		"fr": "Le type de nœud double fournit une haute disponibilité grâce à la réplication.",
		"pt": "O tipo de nó duplo fornece alta disponibilidade através de replicação."
	},
	"recommendation": {
		"en": "Set node_type to \"double\" or \"MASTER_SLAVE\" for the Redis instance.",
		"zh": "将 Redis 实例的 node_type 设置为 \"double\" 或 \"MASTER_SLAVE\"。",
		"ja": "Redis インスタンスの node_type を \"double\" または \"MASTER_SLAVE\" に設定します。",
		"de": "Setzen Sie node_type auf \"double\" oder \"MASTER_SLAVE\" für die Redis-Instanz.",
		"es": "Configure node_type como \"double\" o \"MASTER_SLAVE\" para la instancia Redis.",
		"fr": "Définissez node_type sur \"double\" ou \"MASTER_SLAVE\" pour l'instance Redis.",
		"pt": "Defina node_type como \"double\" ou \"MASTER_SLAVE\" para a instância Redis."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

# Flag if node_type is explicitly "single"
is_single_node(resource) if {
	node_type := tf.get_attribute(resource, "node_type", "double")
	node_type == "single"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	is_single_node(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kvstore_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
