package infraguard.rules.aliyun.hbase_cluster_type_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "hbase-cluster-type-check",
	"name": {
		"en": "HBase Cluster Type Check",
		"zh": "HBase 集群实例类型检测",
		"ja": "HBase クラスタータイプチェック",
		"de": "HBase-Cluster-Typ-Prüfung",
		"es": "Verificación de Tipo de Clúster HBase",
		"fr": "Vérification du Type de Cluster HBase",
		"pt": "Verificação de Tipo de Cluster HBase"
	},
	"severity": "low",
	"description": {
		"en": "Ensures that the HBase cluster is of a specified or recommended type.",
		"zh": "确保 HBase 集群是指定的或推荐的类型。",
		"ja": "HBase クラスターが指定されたまたは推奨されるタイプであることを確認します。",
		"de": "Stellt sicher, dass der HBase-Cluster vom angegebenen oder empfohlenen Typ ist.",
		"es": "Garantiza que el clúster HBase sea de un tipo especificado o recomendado.",
		"fr": "Garantit que le cluster HBase est d'un type spécifié ou recommandé.",
		"pt": "Garante que o cluster HBase seja de um tipo especificado ou recomendado."
	},
	"reason": {
		"en": "Using the correct cluster type ensures optimal performance and support for your workload.",
		"zh": "使用正确的集群类型可确保您的工作负载获得最佳性能和支持。",
		"ja": "正しいクラスタータイプを使用することで、ワークロードに最適なパフォーマンスとサポートが確保されます。",
		"de": "Die Verwendung des richtigen Cluster-Typs gewährleistet optimale Leistung und Unterstützung für Ihre Arbeitslast.",
		"es": "Usar el tipo de clúster correcto garantiza un rendimiento óptimo y soporte para su carga de trabajo.",
		"fr": "L'utilisation du bon type de cluster garantit des performances optimales et un support pour votre charge de travail.",
		"pt": "Usar o tipo de cluster correto garante desempenho ideal e suporte para sua carga de trabalho."
	},
	"recommendation": {
		"en": "Select a recommended HBase cluster type.",
		"zh": "选择推荐的 HBase 集群类型。",
		"ja": "推奨される HBase クラスタータイプを選択します。",
		"de": "Wählen Sie einen empfohlenen HBase-Cluster-Typ.",
		"es": "Seleccione un tipo de clúster HBase recomendado.",
		"fr": "Sélectionnez un type de cluster HBase recommandé.",
		"pt": "Selecione um tipo de cluster HBase recomendado."
	},
	"resource_types": ["ALIYUN::HBase::Cluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::HBase::Cluster")
	helpers.get_property(resource, "ClusterType", "") == "deprecated"
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ClusterType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
