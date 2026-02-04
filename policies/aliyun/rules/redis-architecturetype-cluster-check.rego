package infraguard.rules.aliyun.redis_architecturetype_cluster_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-architecturetype-cluster-check",
	"name": {
		"en": "Redis Architecture Type Cluster Check",
		"zh": "使用集群版的 Redis 实例",
		"ja": "Redis アーキテクチャタイプクラスタチェック",
		"de": "Redis-Architekturtyp Cluster-Prüfung",
		"es": "Verificación de Tipo de Arquitectura de Clúster Redis",
		"fr": "Vérification du Type d'Architecture de Cluster Redis",
		"pt": "Verificação de Tipo de Arquitetura de Cluster Redis",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Redis instance uses cluster architecture type.",
		"zh": "确保 Redis 实例的架构类型为集群版。",
		"ja": "Redis インスタンスがクラスタアーキテクチャタイプを使用することを確認します。",
		"de": "Stellt sicher, dass die Redis-Instanz den Cluster-Architekturtyp verwendet.",
		"es": "Garantiza que la instancia Redis use el tipo de arquitectura de clúster.",
		"fr": "Garantit que l'instance Redis utilise le type d'architecture de cluster.",
		"pt": "Garante que a instância Redis use o tipo de arquitetura de cluster.",
	},
	"reason": {
		"en": "Cluster architecture provides better scalability and high availability.",
		"zh": "集群架构提供更好的可扩展性和高可用性。",
		"ja": "クラスタアーキテクチャは、より優れたスケーラビリティと高可用性を提供します。",
		"de": "Cluster-Architektur bietet bessere Skalierbarkeit und Hochverfügbarkeit.",
		"es": "La arquitectura de clúster proporciona mejor escalabilidad y alta disponibilidad.",
		"fr": "L'architecture de cluster offre une meilleure scalabilité et une haute disponibilité.",
		"pt": "A arquitetura de cluster fornece melhor escalabilidade e alta disponibilidade.",
	},
	"recommendation": {
		"en": "Use cluster architecture for Redis instance.",
		"zh": "为 Redis 实例使用集群架构。",
		"ja": "Redis インスタンスにクラスタアーキテクチャを使用します。",
		"de": "Verwenden Sie Cluster-Architektur für Redis-Instanz.",
		"es": "Use arquitectura de clúster para la instancia Redis.",
		"fr": "Utilisez l'architecture de cluster pour l'instance Redis.",
		"pt": "Use arquitetura de cluster para a instância Redis.",
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "InstanceClass", "")
	contains(instance_class, "cluster")
}

is_compliant(resource) if {
	shard_count := helpers.get_property(resource, "ShardCount", 1)
	shard_count >= 2
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ShardCount"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
