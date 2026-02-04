package infraguard.rules.aliyun.elasticsearch_instance_enabled_node_config_disk_encryption

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "elasticsearch-instance-enabled-node-config-disk-encryption",
	"name": {
		"en": "ES Node Config Disk Encryption",
		"zh": "ES 弹性节点磁盘加密核查",
		"ja": "ES エラスティックノードディスク暗号化",
		"de": "ES-Knoten-Konfiguration Festplattenverschlüsselung",
		"es": "Cifrado de Disco de Configuración de Nodo ES",
		"fr": "Chiffrement de Disque de Configuration de Nœud ES",
		"pt": "Criptografia de Disco de Configuração de Nó ES",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Elasticsearch elastic node configurations have disk encryption enabled.",
		"zh": "确保 Elasticsearch 弹性节点配置开启了磁盘加密。",
		"ja": "Elasticsearch エラスティックノード設定でディスク暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass Elasticsearch-Elastikknoten-Konfigurationen Festplattenverschlüsselung aktiviert haben.",
		"es": "Garantiza que las configuraciones de nodos elásticos de Elasticsearch tengan cifrado de disco habilitado.",
		"fr": "Garantit que les configurations de nœuds élastiques Elasticsearch ont le chiffrement de disque activé.",
		"pt": "Garante que as configurações de nós elásticos do Elasticsearch tenham criptografia de disco habilitada.",
	},
	"reason": {
		"en": "Elastic nodes can store sensitive transient data.",
		"zh": "弹性节点可能存储敏感的临时数据。",
		"ja": "エラスティックノードは機密の一時データを保存する可能性があります。",
		"de": "Elastikknoten können sensible temporäre Daten speichern.",
		"es": "Los nodos elásticos pueden almacenar datos transitorios sensibles.",
		"fr": "Les nœuds élastiques peuvent stocker des données temporaires sensibles.",
		"pt": "Nós elásticos podem armazenar dados transitórios sensíveis.",
	},
	"recommendation": {
		"en": "Enable disk encryption for all node configurations in the ES instance.",
		"zh": "为 Elasticsearch 实例中的所有节点配置开启磁盘加密。",
		"ja": "ES インスタンス内のすべてのノード設定でディスク暗号化を有効にします。",
		"de": "Aktivieren Sie die Festplattenverschlüsselung für alle Knotenkonfigurationen in der ES-Instanz.",
		"es": "Habilite el cifrado de disco para todas las configuraciones de nodos en la instancia ES.",
		"fr": "Activez le chiffrement de disque pour toutes les configurations de nœuds dans l'instance ES.",
		"pt": "Habilite a criptografia de disco para todas as configurações de nós na instância ES.",
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

is_compliant(resource) if {
	# DataNode disk encryption check
	node := helpers.get_property(resource, "DataNode", {})
	helpers.is_true(object.get(node, "DiskEncryption", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DataNode", "DiskEncryption"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
