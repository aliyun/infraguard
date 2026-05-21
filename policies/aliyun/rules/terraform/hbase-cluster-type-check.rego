package infraguard.rules.terraform.hbase_cluster_type_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "hbase-cluster-type-check",
	"severity": "low",
	"name": {
		"en": "HBase Cluster Engine Type Check",
		"zh": "HBase 集群引擎类型检查",
		"ja": "HBase クラスターエンジンタイプチェック",
		"de": "HBase-Cluster Engine-Typ Prufung",
		"es": "Verificacion de Tipo de Motor del Cluster HBase",
		"fr": "Verification du Type de Moteur du Cluster HBase",
		"pt": "Verificacao de Tipo de Motor do Cluster HBase"
	},
	"description": {
		"en": "HBase cluster should not use a deprecated engine type.",
		"zh": "HBase 集群不应使用已废弃的引擎类型。",
		"ja": "HBase クラスターは非推奨のエンジンタイプを使用すべきではありません。",
		"de": "HBase-Cluster sollte keinen veralteten Engine-Typ verwenden.",
		"es": "El cluster HBase no debe usar un tipo de motor obsoleto.",
		"fr": "Le cluster HBase ne doit pas utiliser un type de moteur obsolete.",
		"pt": "O cluster HBase nao deve usar um tipo de motor obsoleto."
	},
	"reason": {
		"en": "The HBase cluster is using a deprecated engine type, which may not receive updates or support.",
		"zh": "HBase 集群使用了已废弃的引擎类型，可能无法获得更新或支持。",
		"ja": "HBase クラスターが非推奨のエンジンタイプを使用しており、更新やサポートを受けられない可能性があります。",
		"de": "Der HBase-Cluster verwendet einen veralteten Engine-Typ, der moglicherweise keine Updates oder Unterstutzung mehr erhalt.",
		"es": "El cluster HBase esta usando un tipo de motor obsoleto, que puede no recibir actualizaciones o soporte.",
		"fr": "Le cluster HBase utilise un type de moteur obsolete, qui peut ne plus recevoir de mises a jour ou de support.",
		"pt": "O cluster HBase esta usando um tipo de motor obsoleto, que pode nao receber atualizacoes ou suporte."
	},
	"recommendation": {
		"en": "Use a supported engine type such as 'hbase' or 'hbaseue' alternatives. Migrate away from deprecated engine types.",
		"zh": "使用受支持的引擎类型。从已废弃的引擎类型迁移。",
		"ja": "サポートされているエンジンタイプを使用してください。非推奨のエンジンタイプから移行してください。",
		"de": "Verwenden Sie einen unterstutzten Engine-Typ. Migrieren Sie von veralteten Engine-Typen.",
		"es": "Utilice un tipo de motor compatible. Migre desde tipos de motor obsoletos.",
		"fr": "Utilisez un type de moteur supporte. Migrez depuis les types de moteur obsoletes.",
		"pt": "Use um tipo de motor suportado. Migre dos tipos de motor obsoletos."
	},
	"resource_types": ["alicloud_hbase_instance"],
	"iac_type": "terraform"
}

deprecated_engines := {"hbaseue"}

is_deprecated_engine(resource) if {
	engine := tf.get_attribute(resource, "engine", "")
	not tf.is_unknown(engine)
	deprecated_engines[engine]
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_hbase_instance")
	is_deprecated_engine(resource)
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
