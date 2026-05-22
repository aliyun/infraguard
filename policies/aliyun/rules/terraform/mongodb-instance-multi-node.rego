package infraguard.rules.terraform.mongodb_instance_multi_node

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-instance-multi-node",
	"severity": "medium",
	"name": {
		"en": "MongoDB Instance Multi-Node for High Availability",
		"zh": "MongoDB 实例多节点高可用",
		"ja": "MongoDB インスタンスが複数のノードを使用",
		"de": "MongoDB-Instanz verwendet mehrere Knoten",
		"es": "La Instancia MongoDB Usa Múltiples Nodos",
		"fr": "L'Instance MongoDB Utilise Plusieurs Nœuds",
		"pt": "A Instância MongoDB Usa Múltiplos Nós"
	},
	"description": {
		"en": "MongoDB instances should have a replication_factor of at least 3 for high availability.",
		"zh": "MongoDB 实例的 replication_factor 应至少为 3 以实现高可用。",
		"ja": "MongoDB インスタンスが高可用性のために複数のノードで展開されていることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen mit mehreren Knoten für Hochverfügbarkeit bereitgestellt werden.",
		"es": "Garantiza que las instancias MongoDB se implementen con múltiples nodos para alta disponibilidad.",
		"fr": "Garantit que les instances MongoDB sont déployées avec plusieurs nœuds pour une haute disponibilité.",
		"pt": "Garante que as instâncias MongoDB sejam implantadas com múltiplos nós para alta disponibilidade."
	},
	"reason": {
		"en": "The MongoDB instance replication_factor is less than 3.",
		"zh": "MongoDB 实例的 replication_factor 小于 3。",
		"ja": "シングルノードインスタンスには冗長性がなく、データ損失やサービス中断のリスクがあります。",
		"de": "Einzelknoten-Instanzen haben keine Redundanz und sind dem Risiko von Datenverlust oder Dienstunterbrechung ausgesetzt.",
		"es": "Las instancias de nodo único no tienen redundancia y corren el riesgo de pérdida de datos o interrupción del servicio.",
		"fr": "Les instances à nœud unique n'ont pas de redondance et risquent une perte de données ou une interruption de service.",
		"pt": "Instâncias de nó único não têm redundância e correm risco de perda de dados ou interrupção do serviço."
	},
	"recommendation": {
		"en": "Set replication_factor to at least 3 for high availability.",
		"zh": "将 replication_factor 设置为至少 3 以实现高可用。",
		"ja": "複数のレプリカセットノードを持つ MongoDB インスタンスを展開します。",
		"de": "Stellen Sie MongoDB-Instanzen mit mehreren Replikat-Set-Knoten bereit.",
		"es": "Implemente instancias MongoDB con múltiples nodos de conjunto de réplicas.",
		"fr": "Déployez des instances MongoDB avec plusieurs nœuds de jeu de répliques.",
		"pt": "Implante instâncias MongoDB com múltiplos nós de conjunto de réplicas."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	replication_factor := tf.get_attribute(resource, "replication_factor", 0)
	replication_factor < 3
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
