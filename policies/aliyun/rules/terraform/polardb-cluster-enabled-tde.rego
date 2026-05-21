package infraguard.rules.terraform.polardb_cluster_enabled_tde

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "polardb-cluster-enabled-tde",
	"severity": "medium",
	"name": {
		"en": "PolarDB Cluster TDE Enabled",
		"zh": "PolarDB 集群开启 TDE",
		"ja": "PolarDB クラスタで TDE が有効",
		"de": "PolarDB-Cluster TDE aktiviert",
		"es": "TDE de Cluster PolarDB Habilitado",
		"fr": "TDE du Cluster PolarDB Activé",
		"pt": "TDE de Cluster PolarDB Habilitado"
	},
	"description": {
		"en": "Ensures PolarDB clusters have Transparent Data Encryption (TDE) enabled.",
		"zh": "确保 PolarDB 集群开启了透明数据加密（TDE）。",
		"ja": "PolarDB クラスタで透過的データ暗号化（TDE）が有効になっていることを確認します。",
		"de": "Stellt sicher, dass PolarDB-Cluster Transparent Data Encryption (TDE) aktiviert haben.",
		"es": "Garantiza que los clústeres PolarDB tengan Transparent Data Encryption (TDE) habilitado.",
		"fr": "Garantit que les clusters PolarDB ont Transparent Data Encryption (TDE) activé.",
		"pt": "Garante que os clusters PolarDB tenham Transparent Data Encryption (TDE) habilitado."
	},
	"reason": {
		"en": "TDE provides data-at-rest encryption for sensitive data stored in the database.",
		"zh": "TDE 为存储在数据库中的敏感数据提供静态数据加密。",
		"ja": "TDE は、データベースに保存されている機密データに対して保存データ暗号化を提供します。",
		"de": "TDE bietet Verschlüsselung ruhender Daten für sensible Daten, die in der Datenbank gespeichert sind.",
		"es": "TDE proporciona cifrado de datos en reposo para datos sensibles almacenados en la base de datos.",
		"fr": "TDE fournit le chiffrement des données au repos pour les données sensibles stockées dans la base de données.",
		"pt": "O TDE fornece criptografia de dados em repouso para dados sensíveis armazenados no banco de dados."
	},
	"recommendation": {
		"en": "Set tde_status to Enabled for the PolarDB cluster.",
		"zh": "为 PolarDB 集群将 tde_status 设置为 Enabled。",
		"ja": "PolarDB クラスタの tde_status を Enabled に設定します。",
		"de": "Setzen Sie tde_status für den PolarDB-Cluster auf Enabled.",
		"es": "Establezca tde_status en Enabled para el clúster PolarDB.",
		"fr": "Définissez tde_status sur Enabled pour le cluster PolarDB.",
		"pt": "Defina tde_status como Enabled para o cluster PolarDB."
	},
	"resource_types": ["alicloud_polardb_cluster"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_polardb_cluster")
	tf.get_attribute(resource, "tde_status", "Disabled") != "Enabled"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_polardb_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
