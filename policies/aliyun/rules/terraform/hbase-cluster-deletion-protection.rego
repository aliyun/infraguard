package infraguard.rules.terraform.hbase_cluster_deletion_protection

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "hbase-cluster-deletion-protection",
	"severity": "high",
	"name": {
		"en": "HBase Cluster Deletion Protection Enabled",
		"zh": "HBase 集群开启释放保护",
		"ja": "HBase クラスター削除保護が有効",
		"de": "HBase-Cluster Löschschutz aktiviert",
		"es": "Proteccion de Eliminacion de Cluster HBase Habilitada",
		"fr": "Protection contre la Suppression du Cluster HBase Activee",
		"pt": "Protecao contra Exclusao do Cluster HBase Habilitada"
	},
	"description": {
		"en": "Ensures that HBase instances have deletion protection enabled.",
		"zh": "确保 HBase 实例开启了释放保护。",
		"ja": "HBase インスタンスで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass HBase-Instanzen Loschschutz aktiviert haben.",
		"es": "Garantiza que las instancias HBase tengan proteccion contra eliminacion habilitada.",
		"fr": "Garantit que les instances HBase ont la protection contre la suppression activee.",
		"pt": "Garante que as instancias HBase tenham protecao contra exclusao habilitada."
	},
	"reason": {
		"en": "If deletion protection is not enabled, the HBase instance may be released accidentally, causing data loss.",
		"zh": "如果未开启释放保护，HBase 实例可能会被意外释放，导致数据丢失。",
		"ja": "削除保護が有効になっていない場合、HBase インスタンスが誤って解放され、データ損失が発生する可能性があります。",
		"de": "Wenn der Loschschutz nicht aktiviert ist, kann die HBase-Instanz versehentlich freigegeben werden, was zu Datenverlust fuhrt.",
		"es": "Si la proteccion contra eliminacion no esta habilitada, la instancia HBase puede ser liberada accidentalmente, causando perdida de datos.",
		"fr": "Si la protection contre la suppression n'est pas activee, l'instance HBase peut etre liberee accidentellement, entrainant une perte de donnees.",
		"pt": "Se a protecao contra exclusao nao estiver habilitada, a instancia HBase pode ser liberada acidentalmente, causando perda de dados."
	},
	"recommendation": {
		"en": "Enable deletion protection for the HBase instance.",
		"zh": "为 HBase 实例开启释放保护功能。",
		"ja": "HBase インスタンスの削除保護を有効にします。",
		"de": "Aktivieren Sie den Loschschutz fur die HBase-Instanz.",
		"es": "Habilite la proteccion contra eliminacion para la instancia HBase.",
		"fr": "Activez la protection contre la suppression pour l'instance HBase.",
		"pt": "Habilite a protecao contra exclusao para a instancia HBase."
	},
	"resource_types": ["alicloud_hbase_instance"],
	"iac_type": "terraform"
}

is_compliant(resource) if {
	tf.get_attribute(resource, "deletion_protection", false) == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_hbase_instance")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_hbase_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
