package infraguard.rules.aliyun.mongodb_instance_multi_node

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-instance-multi-node",
	"severity": "medium",
	"name": {
		"en": "MongoDB Instance Uses Multiple Nodes",
		"zh": "使用多节点的 MongoDB 实例",
		"ja": "MongoDB インスタンスが複数のノードを使用",
		"de": "MongoDB-Instanz verwendet mehrere Knoten",
		"es": "La Instancia MongoDB Usa Múltiples Nodos",
		"fr": "L'Instance MongoDB Utilise Plusieurs Nœuds",
		"pt": "A Instância MongoDB Usa Múltiplos Nós"
	},
	"description": {
		"en": "Ensures MongoDB instances are deployed with multiple nodes for high availability.",
		"zh": "确保 MongoDB 实例部署了多个节点以实现高可用性。",
		"ja": "MongoDB インスタンスが高可用性のために複数のノードで展開されていることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen mit mehreren Knoten für Hochverfügbarkeit bereitgestellt werden.",
		"es": "Garantiza que las instancias MongoDB se implementen con múltiples nodos para alta disponibilidad.",
		"fr": "Garantit que les instances MongoDB sont déployées avec plusieurs nœuds pour une haute disponibilité.",
		"pt": "Garante que as instâncias MongoDB sejam implantadas com múltiplos nós para alta disponibilidade."
	},
	"reason": {
		"en": "Single-node instances have no redundancy and are at risk of data loss or service interruption.",
		"zh": "单节点实例没有冗余，存在数据丢失或服务中断的风险。",
		"ja": "シングルノードインスタンスには冗長性がなく、データ損失やサービス中断のリスクがあります。",
		"de": "Einzelknoten-Instanzen haben keine Redundanz und sind dem Risiko von Datenverlust oder Dienstunterbrechung ausgesetzt.",
		"es": "Las instancias de nodo único no tienen redundancia y corren el riesgo de pérdida de datos o interrupción del servicio.",
		"fr": "Les instances à nœud unique n'ont pas de redondance et risquent une perte de données ou une interruption de service.",
		"pt": "Instâncias de nó único não têm redundância e correm risco de perda de dados ou interrupção do serviço."
	},
	"recommendation": {
		"en": "Deploy MongoDB instances with multiple replica set nodes.",
		"zh": "部署具有多个副本集节点的 MongoDB 实例。",
		"ja": "複数のレプリカセットノードを持つ MongoDB インスタンスを展開します。",
		"de": "Stellen Sie MongoDB-Instanzen mit mehreren Replikat-Set-Knoten bereit.",
		"es": "Implemente instancias MongoDB con múltiples nodos de conjunto de réplicas.",
		"fr": "Déployez des instances MongoDB avec plusieurs nœuds de jeu de répliques.",
		"pt": "Implante instâncias MongoDB com múltiplos nós de conjunto de réplicas."
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"]
}

# Check if instance has multiple nodes
is_compliant(resource) if {
	replication_factor := helpers.get_property(resource, "ReplicationFactor", 0)
	replication_factor >= 3
}

is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")

	# Check if it's a replica set class (typically contains 'replica' or has specific patterns)
	contains(lower(instance_class), "replica")
}

is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")
	contains(lower(instance_class), "sharding")
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ReplicationFactor"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
