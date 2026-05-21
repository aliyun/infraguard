package infraguard.rules.terraform.elasticsearch_instance_enabled_data_node_encryption

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "elasticsearch-instance-enabled-data-node-encryption",
	"severity": "medium",
	"name": {"en": "Elasticsearch Data Node Encryption Enabled", "zh": "Elasticsearch 数据节点开启加密", "ja": "Elasticsearch データノード暗号化が有効", "de": "Elasticsearch-Datenknoten-Verschlüsselung aktiviert", "es": "Cifrado de Nodo de Datos de Elasticsearch Habilitado", "fr": "Chiffrement du Nœud de Données Elasticsearch Activé", "pt": "Criptografia de Nó de Dados do Elasticsearch Habilitada"},
	"description": {"en": "Ensures that data nodes in the Elasticsearch instance have disk encryption enabled.", "zh": "确保 Elasticsearch 实例中的数据节点已开启磁盘加密。", "ja": "Elasticsearch インスタンス内のデータノードでディスク暗号化が有効になっていることを確認します。", "de": "Stellt sicher, dass Datenknoten in der Elasticsearch-Instanz Disk-Verschlüsselung aktiviert haben.", "es": "Garantiza que los nodos de datos en la instancia de Elasticsearch tengan cifrado de disco habilitado.", "fr": "Garantit que les nœuds de données dans l'instance Elasticsearch ont le chiffrement de disque activé.", "pt": "Garante que os nós de dados na instância do Elasticsearch tenham criptografia de disco habilitada."},
	"reason": {"en": "Disk encryption protects sensitive data stored on Elasticsearch nodes.", "zh": "磁盘加密可保护存储在 Elasticsearch 节点上的敏感数据。", "ja": "ディスク暗号化により、Elasticsearch ノードに保存されている機密データが保護されます。", "de": "Disk-Verschlüsselung schützt sensible Daten, die auf Elasticsearch-Knoten gespeichert sind.", "es": "El cifrado de disco protege los datos sensibles almacenados en los nodos de Elasticsearch.", "fr": "Le chiffrement de disque protège les données sensibles stockées sur les nœuds Elasticsearch.", "pt": "A criptografia de disco protege dados sensíveis armazenados nos nós do Elasticsearch."},
	"recommendation": {"en": "Enable disk encryption for the Elasticsearch instance data nodes.", "zh": "为 Elasticsearch 实例数据节点开启磁盘加密。", "ja": "Elasticsearch インスタンスのデータノードでディスク暗号化を有効にします。", "de": "Aktivieren Sie Disk-Verschlüsselung für die Datenknoten der Elasticsearch-Instanz.", "es": "Habilite el cifrado de disco para los nodos de datos de la instancia de Elasticsearch.", "fr": "Activez le chiffrement de disque pour les nœuds de données de l'instance Elasticsearch.", "pt": "Habilite a criptografia de disco para os nós de dados da instância do Elasticsearch."},
	"resource_types": ["alicloud_elasticsearch_instance"],
	"iac_type": "terraform"
}

is_encrypted(resource) if {
	data_node := tf.get_attribute(resource, "data_node", {})
	not tf.is_unknown(data_node)
	data_node.disk_encryption == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_elasticsearch_instance")
	not is_encrypted(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_elasticsearch_instance.%s", [name]),
		"violation_path": ["data_node", "disk_encryption"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
