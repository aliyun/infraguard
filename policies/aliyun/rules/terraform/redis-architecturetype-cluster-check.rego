package infraguard.rules.terraform.redis_architecturetype_cluster_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-architecturetype-cluster-check",
	"severity": "medium",
	"name": {
		"en": "Redis Architecture Type Cluster Check",
		"zh": "使用集群版的 Redis 实例",
		"ja": "Redis アーキテクチャタイプクラスタチェック",
		"de": "Redis-Architekturtyp Cluster-Prüfung",
		"es": "Verificación de Tipo de Arquitectura de Clúster Redis",
		"fr": "Vérification du Type d'Architecture de Cluster Redis",
		"pt": "Verificação de Tipo de Arquitetura de Cluster Redis"
	},
	"description": {
		"en": "Ensures Redis instance uses cluster architecture type.",
		"zh": "确保 Redis 实例的架构类型为集群版。",
		"ja": "Redis インスタンスがクラスタアーキテクチャタイプを使用することを確認します。",
		"de": "Stellt sicher, dass die Redis-Instanz den Cluster-Architekturtyp verwendet.",
		"es": "Garantiza que la instancia Redis use el tipo de arquitectura de clúster.",
		"fr": "Garantit que l'instance Redis utilise le type d'architecture de cluster.",
		"pt": "Garante que a instância Redis use o tipo de arquitetura de cluster."
	},
	"reason": {
		"en": "Cluster architecture provides better scalability and high availability.",
		"zh": "集群架构提供更好的可扩展性和高可用性。",
		"ja": "クラスタアーキテクチャは、より優れたスケーラビリティと高可用性を提供します。",
		"de": "Cluster-Architektur bietet bessere Skalierbarkeit und Hochverfügbarkeit.",
		"es": "La arquitectura de clúster proporciona mejor escalabilidad y alta disponibilidad.",
		"fr": "L'architecture de cluster offre une meilleure scalabilité et une haute disponibilité.",
		"pt": "A arquitetura de cluster fornece melhor escalabilidade e alta disponibilidade."
	},
	"recommendation": {
		"en": "Use cluster architecture by setting instance_class to a cluster type or shard_number >= 2.",
		"zh": "通过设置 instance_class 为集群类型或 shard_number >= 2 来使用集群架构。",
		"ja": "instance_class をクラスタタイプに設定するか、shard_number >= 2 に設定してクラスタアーキテクチャを使用します。",
		"de": "Verwenden Sie Cluster-Architektur, indem Sie instance_class auf einen Cluster-Typ oder shard_number >= 2 setzen.",
		"es": "Use arquitectura de clúster configurando instance_class a un tipo de clúster o shard_number >= 2.",
		"fr": "Utilisez l'architecture de cluster en définissant instance_class sur un type cluster ou shard_number >= 2.",
		"pt": "Use arquitetura de cluster configurando instance_class para um tipo cluster ou shard_number >= 2."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

# Compliant if instance_class contains "cluster"
is_cluster(resource) if {
	instance_class := tf.get_attribute(resource, "instance_class", "")
	contains(instance_class, "cluster")
}

# Compliant if shard_number >= 2
is_cluster(resource) if {
	shard_number := tf.get_attribute(resource, "shard_number", 1)
	shard_number >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	not is_cluster(resource)
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
