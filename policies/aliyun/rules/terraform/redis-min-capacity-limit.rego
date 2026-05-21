package infraguard.rules.terraform.redis_min_capacity_limit

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-min-capacity-limit",
	"severity": "medium",
	"name": {
		"en": "Redis Min Capacity Limit",
		"zh": "Redis 实例满足指定内存容量要求",
		"ja": "Redis 最小容量制限",
		"de": "Redis Mindestkapazitätsgrenze",
		"es": "Límite de Capacidad Mínima de Redis",
		"fr": "Limite de Capacité Minimale Redis",
		"pt": "Limite de Capacidade Mínima do Redis"
	},
	"description": {
		"en": "Ensures Redis instance has memory capacity meeting the minimum requirement.",
		"zh": "确保 Redis 实例内存总量大于等于指定的参数值。",
		"ja": "Redis インスタンスが最小要件を満たすメモリ容量を持っていることを確認します。",
		"de": "Stellt sicher, dass die Redis-Instanz eine Speicherkapazität hat, die die Mindestanforderung erfüllt.",
		"es": "Garantiza que la instancia Redis tenga capacidad de memoria que cumpla con el requisito mínimo.",
		"fr": "Garantit que l'instance Redis a une capacité mémoire répondant à l'exigence minimale.",
		"pt": "Garante que a instância Redis tenha capacidade de memória que atenda ao requisito mínimo."
	},
	"reason": {
		"en": "Adequate memory ensures Redis can handle the workload.",
		"zh": "充足的内存确保 Redis 能够处理工作负载。",
		"ja": "十分なメモリにより、Redis がワークロードを処理できることが保証されます。",
		"de": "Ausreichender Speicher stellt sicher, dass Redis die Arbeitslast bewältigen kann.",
		"es": "La memoria adecuada garantiza que Redis pueda manejar la carga de trabajo.",
		"fr": "Une mémoire adéquate garantit que Redis peut gérer la charge de travail.",
		"pt": "Memória adequada garante que o Redis possa lidar com a carga de trabalho."
	},
	"recommendation": {
		"en": "Ensure Redis instance capacity is at least 1024 MB.",
		"zh": "确保 Redis 实例容量至少为 1024 MB。",
		"ja": "Redis インスタンスの容量が少なくとも 1024 MB であることを確認します。",
		"de": "Stellen Sie sicher, dass die Redis-Instanz-Kapazität mindestens 1024 MB beträgt.",
		"es": "Asegúrese de que la capacidad de la instancia Redis sea al menos 1024 MB.",
		"fr": "Assurez-vous que la capacité de l'instance Redis est d'au moins 1024 Mo.",
		"pt": "Garanta que a capacidade da instância Redis seja pelo menos 1024 MB."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

is_compliant(_resource) := true

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	not is_compliant(resource)
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
