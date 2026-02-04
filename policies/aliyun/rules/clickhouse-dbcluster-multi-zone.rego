package infraguard.rules.aliyun.clickhouse_dbcluster_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "clickhouse-dbcluster-multi-zone",
	"name": {
		"en": "ClickHouse DBCluster Multi-Zone Deployment",
		"zh": "使用多可用区的 ClickHouse 集群实例",
		"ja": "ClickHouse DBCluster マルチゾーン展開",
		"de": "ClickHouse DBCluster Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de ClickHouse DBCluster",
		"fr": "Déploiement Multi-Zone ClickHouse DBCluster",
		"pt": "Implantações Multi-Zona do ClickHouse DBCluster",
	},
	"severity": "medium",
	"description": {
		"en": "ClickHouse clusters should use the HighAvailability (Double-replica) edition for multi-zone deployment. Note: This applies only to community edition.",
		"zh": "使用多可用区的 ClickHouse 集群实例，视为合规，注意只包含社区版本。",
		"ja": "ClickHouse クラスタはマルチゾーン展開に HighAvailability（ダブルレプリカ）エディションを使用する必要があります。注：これはコミュニティエディションにのみ適用されます。",
		"de": "ClickHouse-Cluster sollten die HighAvailability (Double-Replica) Edition für Multi-Zone-Bereitstellung verwenden. Hinweis: Dies gilt nur für die Community-Edition.",
		"es": "Los clústeres ClickHouse deben usar la edición HighAvailability (Double-replica) para despliegue multi-zona. Nota: Esto se aplica solo a la edición comunitaria.",
		"fr": "Les clusters ClickHouse doivent utiliser l'édition HighAvailability (Double-replica) pour le déploiement multi-zone. Note : Cela s'applique uniquement à l'édition communautaire.",
		"pt": "Os clusters ClickHouse devem usar a edição HighAvailability (Double-replica) para implantação multi-zona. Nota: Isso se aplica apenas à edição da comunidade.",
	},
	"reason": {
		"en": "The ClickHouse cluster is using Single-replica Edition, which does not provide multi-zone high availability.",
		"zh": "ClickHouse 集群使用单副本版本，不提供多可用区高可用性。",
		"ja": "ClickHouse クラスタはシングルレプリカエディションを使用しており、マルチゾーン高可用性を提供しません。",
		"de": "Der ClickHouse-Cluster verwendet die Single-Replica-Edition, die keine Multi-Zone-Hochverfügbarkeit bietet.",
		"es": "El clúster ClickHouse está usando la edición Single-replica, que no proporciona alta disponibilidad multi-zona.",
		"fr": "Le cluster ClickHouse utilise l'édition Single-replica, qui ne fournit pas de haute disponibilité multi-zone.",
		"pt": "O cluster ClickHouse está usando a edição Single-replica, que não fornece alta disponibilidade multi-zona.",
	},
	"recommendation": {
		"en": "Use the HighAvailability (Double-replica) edition by setting Category to 'HighAvailability' for multi-zone deployment.",
		"zh": "通过将 Category 设置为'HighAvailability'来使用双副本版本，实现多可用区部署。",
		"ja": "マルチゾーン展開のために、Category を 'HighAvailability' に設定して HighAvailability（ダブルレプリカ）エディションを使用します。",
		"de": "Verwenden Sie die HighAvailability (Double-Replica) Edition, indem Sie Category auf 'HighAvailability' setzen für Multi-Zone-Bereitstellung.",
		"es": "Use la edición HighAvailability (Double-replica) estableciendo Category en 'HighAvailability' para despliegue multi-zona.",
		"fr": "Utilisez l'édition HighAvailability (Double-replica) en définissant Category sur 'HighAvailability' pour le déploiement multi-zone.",
		"pt": "Use a edição HighAvailability (Double-replica) definindo Category como 'HighAvailability' para implantação multi-zona.",
	},
	"resource_types": ["ALIYUN::ClickHouse::DBCluster"],
}

# Check if cluster is high availability (multi-zone)
is_high_availability(resource) if {
	category := resource.Properties.Category
	category == "HighAvailability"
}

# Deny rule: ClickHouse clusters should use HighAvailability edition
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ClickHouse::DBCluster")
	not is_high_availability(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Category"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
