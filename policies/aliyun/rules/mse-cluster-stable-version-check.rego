package infraguard.rules.aliyun.mse_cluster_stable_version_check

import rego.v1

import data.infraguard.helpers

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
		"en": "Ensures that MSE cluster engine version is greater than the minimum stable version.",
		"zh": "确保 MSE 集群引擎版本大于最小稳定版本。",
		"ja": "MSE クラスターエンジンバージョンが最小安定バージョンより大きいことを確認します。",
		"de": "Stellt sicher, dass die MSE-Cluster-Engine-Version größer als die minimale stabile Version ist.",
		"es": "Garantiza que la versión del motor del clúster MSE sea mayor que la versión estable mínima.",
		"fr": "Garantit que la version du moteur du cluster MSE est supérieure à la version stable minimale.",
		"pt": "Garante que a versão do motor do cluster MSE seja maior que a versão estável mínima."
	},
	"reason": {
		"en": "Older versions may have security vulnerabilities and lack latest features.",
		"zh": "旧版本可能存在安全漏洞且缺少最新功能。",
		"ja": "古いバージョンにはセキュリティの脆弱性があり、最新機能が不足している可能性があります。",
		"de": "Ältere Versionen können Sicherheitslücken haben und die neuesten Funktionen fehlen.",
		"es": "Las versiones anteriores pueden tener vulnerabilidades de seguridad y carecer de las últimas funciones.",
		"fr": "Les versions antérieures peuvent avoir des vulnérabilités de sécurité et manquer des fonctionnalités les plus récentes.",
		"pt": "Versões mais antigas podem ter vulnerabilidades de segurança e faltar recursos mais recentes."
	},
	"recommendation": {
		"en": "Upgrade the MSE cluster to a stable version.",
		"zh": "将 MSE 集群升级到稳定版本。",
		"ja": "MSE クラスターを安定バージョンにアップグレードします。",
		"de": "Aktualisieren Sie den MSE-Cluster auf eine stabile Version.",
		"es": "Actualice el clúster MSE a una versión estable.",
		"fr": "Mettez à niveau le cluster MSE vers une version stable.",
		"pt": "Atualize o cluster MSE para uma versão estável."
	},
	"resource_types": ["ALIYUN::MSE::Cluster"]
}

# Default minimum stable version
default_min_version := "3.5.0"

# Get minimum version from parameter or use default
get_min_version := version if {
	version := input.parameters.minVersion
	is_string(version)
} else := default_min_version

# Compare version strings (simple implementation)
version_greater(v1, v2) if {
	v1_parts := split(v1, ".")
	v2_parts := split(v2, ".")

	# Compare major version
	to_number(v1_parts[0]) > to_number(v2_parts[0])
}

version_greater(v1, v2) if {
	v1_parts := split(v1, ".")
	v2_parts := split(v2, ".")

	# Major versions equal, compare minor
	to_number(v1_parts[0]) == to_number(v2_parts[0])
	to_number(v1_parts[1]) > to_number(v2_parts[1])
}

# Check if cluster version is stable
is_stable_version(resource) if {
	cluster_version := helpers.get_property(resource, "ClusterVersion", "")
	cluster_version != ""

	# Extract version number from ClusterVersion (e.g., "ZooKeeper_3_8_0" -> "3.8.0")
	version_parts := split(cluster_version, "_")
	count(version_parts) >= 4

	# For "ZooKeeper_3_8_0", parts are ["ZooKeeper", "3", "8", "0"]
	major := version_parts[1]
	minor := version_parts[2]
	patch := version_parts[3]
	version := sprintf("%s.%s.%s", [major, minor, patch])
	version_greater(version, get_min_version())
}

is_compliant(resource) if {
	is_stable_version(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Cluster")
	not is_stable_version(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ClusterVersion"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
