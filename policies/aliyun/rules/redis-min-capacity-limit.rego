package infraguard.rules.aliyun.redis_min_capacity_limit

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-min-capacity-limit",
	"name": {
		"en": "Redis Min Capacity Limit",
		"zh": "Redis 实例满足指定内存容量要求",
		"ja": "Redis 最小容量制限",
		"de": "Redis Mindestkapazitätsgrenze",
		"es": "Límite de Capacidad Mínima de Redis",
		"fr": "Limite de Capacité Minimale Redis",
		"pt": "Limite de Capacidade Mínima do Redis"
	},
	"severity": "medium",
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
		"en": "Ensure Redis instance has minimum required memory capacity.",
		"zh": "确保 Redis 实例满足最低内存容量要求。",
		"ja": "Redis インスタンスが最小必要なメモリ容量を持っていることを確認します。",
		"de": "Stellen Sie sicher, dass die Redis-Instanz die mindestens erforderliche Speicherkapazität hat.",
		"es": "Asegúrese de que la instancia Redis tenga la capacidad de memoria mínima requerida.",
		"fr": "Assurez-vous que l'instance Redis a la capacité mémoire minimale requise.",
		"pt": "Garanta que a instância Redis tenha a capacidade de memória mínima necessária."
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	capacity := helpers.get_property(resource, "Capacity", 1024)
	capacity >= 1024
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Capacity"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
