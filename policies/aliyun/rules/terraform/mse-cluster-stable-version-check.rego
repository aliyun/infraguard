package infraguard.rules.terraform.mse_cluster_stable_version_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mse-cluster-stable-version-check",
	"severity": "medium",
	"name": {
		"en": "MSE Cluster Uses Stable Version",
		"zh": "MSE 注册配置中心引擎版本检测",
		"ja": "MSE クラスターが安定バージョンを使用",
		"de": "MSE-Cluster verwendet stabile Version",
		"es": "El Clúster MSE Usa Versión Estable",
		"fr": "Le Cluster MSE Utilise une Version Stable",
		"pt": "O Cluster MSE Usa Versão Estável"
	},
	"description": {
		"en": "MSE cluster should have a cluster_version explicitly set and not empty.",
		"zh": "MSE 集群应明确设置 cluster_version 且不为空。",
		"ja": "MSE クラスターエンジンバージョンが最小安定バージョンより大きいことを確認します。",
		"de": "Stellt sicher, dass die MSE-Cluster-Engine-Version größer als die minimale stabile Version ist.",
		"es": "Garantiza que la versión del motor del clúster MSE sea mayor que la versión estable mínima.",
		"fr": "Garantit que la version du moteur du cluster MSE est supérieure à la version stable minimale.",
		"pt": "Garante que a versão do motor do cluster MSE seja maior que a versão estável mínima."
	},
	"reason": {
		"en": "The MSE cluster does not have cluster_version set.",
		"zh": "MSE 集群未设置 cluster_version。",
		"ja": "古いバージョンにはセキュリティの脆弱性があり、最新機能が不足している可能性があります。",
		"de": "Ältere Versionen können Sicherheitslücken haben und die neuesten Funktionen fehlen.",
		"es": "Las versiones anteriores pueden tener vulnerabilidades de seguridad y carecer de las últimas funciones.",
		"fr": "Les versions antérieures peuvent avoir des vulnérabilités de sécurité et manquer des fonctionnalités les plus récentes.",
		"pt": "Versões mais antigas podem ter vulnerabilidades de segurança e faltar recursos mais recentes."
	},
	"recommendation": {
		"en": "Set cluster_version to a specific stable version (e.g., 'NACOS_2_0_0').",
		"zh": "将 cluster_version 设置为特定的稳定版本（如 'NACOS_2_0_0'）。",
		"ja": "MSE クラスターを安定バージョンにアップグレードします。",
		"de": "Aktualisieren Sie den MSE-Cluster auf eine stabile Version.",
		"es": "Actualice el clúster MSE a una versión estable.",
		"fr": "Mettez à niveau le cluster MSE vers une version stable.",
		"pt": "Atualize o cluster MSE para uma versão estável."
	},
	"resource_types": ["alicloud_mse_cluster"],
	"iac_type": "terraform"
}

has_cluster_version(resource) if {
	cluster_version := tf.get_attribute(resource, "cluster_version", "")
	not tf.is_unknown(cluster_version)
	cluster_version != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mse_cluster")
	not has_cluster_version(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mse_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
