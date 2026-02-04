package infraguard.rules.aliyun.hbase_cluster_deletion_protection

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "hbase-cluster-deletion-protection",
	"severity": "medium",
	"name": {
		"en": "HBase Cluster Deletion Protection Enabled",
		"zh": "HBase 集群开启删除保护",
		"ja": "HBase クラスタ削除保護が有効",
		"de": "HBase-Cluster Löschschutz aktiviert",
		"es": "Protección de Eliminación de Clúster HBase Habilitada",
		"fr": "Protection contre la Suppression de Cluster HBase Activée",
		"pt": "Proteção contra Exclusão de Cluster HBase Habilitada"
	},
	"description": {
		"en": "Ensures that HBase clusters have deletion protection enabled.",
		"zh": "确保 HBase 集群开启了删除保护。",
		"ja": "HBase クラスタで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass HBase-Cluster Löschschutz aktiviert haben.",
		"es": "Garantiza que los clústeres HBase tengan protección contra eliminación habilitada.",
		"fr": "Garantit que les clusters HBase ont la protection contre la suppression activée.",
		"pt": "Garante que os clusters HBase tenham proteção contra exclusão habilitada."
	},
	"reason": {
		"en": "If deletion protection is not enabled, the HBase cluster may be released accidentally, causing data loss.",
		"zh": "如果未开启删除保护，HBase 集群可能会被意外释放，导致数据丢失。",
		"ja": "削除保護が有効になっていない場合、HBase クラスタが誤って解放され、データ損失が発生する可能性があります。",
		"de": "Wenn der Löschschutz nicht aktiviert ist, kann der HBase-Cluster versehentlich freigegeben werden, was zu Datenverlust führt.",
		"es": "Si la protección contra eliminación no está habilitada, el clúster HBase puede ser liberado accidentalmente, causando pérdida de datos.",
		"fr": "Si la protection contre la suppression n'est pas activée, le cluster HBase peut être libéré accidentellement, entraînant une perte de données.",
		"pt": "Se a proteção contra exclusão não estiver habilitada, o cluster HBase pode ser liberado acidentalmente, causando perda de dados."
	},
	"recommendation": {
		"en": "Enable deletion protection for the HBase cluster.",
		"zh": "为 HBase 集群开启删除保护功能。",
		"ja": "HBase クラスタの削除保護を有効にします。",
		"de": "Aktivieren Sie den Löschschutz für den HBase-Cluster.",
		"es": "Habilite la protección contra eliminación para el clúster HBase.",
		"fr": "Activez la protection contre la suppression pour le cluster HBase.",
		"pt": "Habilite a proteção contra exclusão para o cluster HBase."
	},
	"resource_types": ["ALIYUN::HBase::Cluster"]
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::HBase::Cluster")
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
