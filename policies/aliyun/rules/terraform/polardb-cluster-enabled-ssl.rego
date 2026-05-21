package infraguard.rules.terraform.polardb_cluster_enabled_ssl

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "polardb-cluster-enabled-ssl",
	"severity": "medium",
	"name": {
		"en": "PolarDB Cluster SSL Enabled",
		"zh": "PolarDB 集群开启 SSL 加密",
		"ja": "PolarDB クラスタで SSL が有効",
		"de": "PolarDB-Cluster SSL aktiviert",
		"es": "SSL de Cluster PolarDB Habilitado",
		"fr": "SSL du Cluster PolarDB Activé",
		"pt": "SSL de Cluster PolarDB Habilitado"
	},
	"description": {
		"en": "Ensures PolarDB clusters have SSL encryption enabled.",
		"zh": "确保 PolarDB 集群开启了 SSL 加密。",
		"ja": "PolarDB クラスタで SSL 暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass PolarDB-Cluster SSL-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que los clústeres PolarDB tengan cifrado SSL habilitado.",
		"fr": "Garantit que les clusters PolarDB ont le chiffrement SSL activé.",
		"pt": "Garante que os clusters PolarDB tenham criptografia SSL habilitada."
	},
	"reason": {
		"en": "SSL encryption secures the communication between applications and the database cluster.",
		"zh": "SSL 加密保障了应用程序与数据库集群之间的通信安全。",
		"ja": "SSL 暗号化により、アプリケーションとデータベースクラスタ間の通信が保護されます。",
		"de": "SSL-Verschlüsselung sichert die Kommunikation zwischen Anwendungen und dem Datenbankcluster.",
		"es": "El cifrado SSL protege la comunicación entre aplicaciones y el clúster de base de datos.",
		"fr": "Le chiffrement SSL sécurise la communication entre les applications et le cluster de base de données.",
		"pt": "A criptografia SSL protege a comunicação entre aplicações e o cluster de banco de dados."
	},
	"recommendation": {
		"en": "Set tde_status to Enabled for the PolarDB cluster to enable encryption.",
		"zh": "为 PolarDB 集群将 tde_status 设置为 Enabled 以启用加密。",
		"ja": "暗号化を有効にするには、PolarDB クラスタの tde_status を Enabled に設定します。",
		"de": "Setzen Sie tde_status für den PolarDB-Cluster auf Enabled, um Verschlüsselung zu aktivieren.",
		"es": "Establezca tde_status en Enabled para el clúster PolarDB para habilitar el cifrado.",
		"fr": "Définissez tde_status sur Enabled pour le cluster PolarDB pour activer le chiffrement.",
		"pt": "Defina tde_status como Enabled para o cluster PolarDB para habilitar criptografia."
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
