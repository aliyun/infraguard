package infraguard.rules.aliyun.polardb_cluster_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "polardb-cluster-delete-protection-enabled",
	"name": {
		"en": "PolarDB Cluster Deletion Protection Enabled",
		"zh": "PolarDB 集群开启删除保护",
		"ja": "PolarDB クラスタの削除保護が有効",
		"de": "PolarDB-Cluster-Löschschutz aktiviert",
		"es": "Protección contra Eliminación de Cluster PolarDB Habilitada",
		"fr": "Protection contre la Suppression du Cluster PolarDB Activée",
		"pt": "Proteção contra Exclusão de Cluster PolarDB Habilitada",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that PolarDB clusters have deletion protection enabled.",
		"zh": "确保 PolarDB 集群开启了删除保护。",
		"ja": "PolarDB クラスタで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass PolarDB-Cluster den Löschschutz aktiviert haben.",
		"es": "Garantiza que los clústeres PolarDB tengan protección contra eliminación habilitada.",
		"fr": "Garantit que les clusters PolarDB ont la protection contre la suppression activée.",
		"pt": "Garante que os clusters PolarDB tenham proteção contra exclusão habilitada.",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the PolarDB cluster may be released accidentally, causing data loss.",
		"zh": "如果未开启删除保护，PolarDB 集群可能会被意外释放，导致数据丢失。",
		"ja": "削除保護が有効になっていない場合、PolarDB クラスタが誤って解放され、データ損失が発生する可能性があります。",
		"de": "Wenn der Löschschutz nicht aktiviert ist, kann der PolarDB-Cluster versehentlich freigegeben werden, was zu Datenverlust führt.",
		"es": "Si la protección contra eliminación no está habilitada, el clúster PolarDB puede ser liberado accidentalmente, causando pérdida de datos.",
		"fr": "Si la protection contre la suppression n'est pas activée, le cluster PolarDB peut être libéré accidentellement, causant une perte de données.",
		"pt": "Se a proteção contra exclusão não estiver habilitada, o cluster PolarDB pode ser liberado acidentalmente, causando perda de dados.",
	},
	"recommendation": {
		"en": "Enable deletion protection for the PolarDB cluster.",
		"zh": "为 PolarDB 集群开启删除保护功能。",
		"ja": "PolarDB クラスタで削除保護を有効にします。",
		"de": "Aktivieren Sie den Löschschutz für den PolarDB-Cluster.",
		"es": "Habilite protección contra eliminación para el clúster PolarDB.",
		"fr": "Activez la protection contre la suppression pour le cluster PolarDB.",
		"pt": "Habilite proteção contra exclusão para o cluster PolarDB.",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeletionProtection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
