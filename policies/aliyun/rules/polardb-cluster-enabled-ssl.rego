package infraguard.rules.aliyun.polardb_cluster_enabled_ssl

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "polardb-cluster-enabled-ssl",
	"name": {
		"en": "PolarDB Cluster SSL Enabled",
		"zh": "PolarDB 集群开启 SSL 加密",
		"ja": "PolarDB クラスタで SSL が有効",
		"de": "PolarDB-Cluster SSL aktiviert",
		"es": "SSL de Cluster PolarDB Habilitado",
		"fr": "SSL du Cluster PolarDB Activé",
		"pt": "SSL de Cluster PolarDB Habilitado",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures PolarDB clusters have SSL encryption enabled.",
		"zh": "确保 PolarDB 集群开启了 SSL 加密。",
		"ja": "PolarDB クラスタで SSL 暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass PolarDB-Cluster SSL-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que los clústeres PolarDB tengan cifrado SSL habilitado.",
		"fr": "Garantit que les clusters PolarDB ont le chiffrement SSL activé.",
		"pt": "Garante que os clusters PolarDB tenham criptografia SSL habilitada.",
	},
	"reason": {
		"en": "SSL encryption secures the communication between applications and the database cluster.",
		"zh": "SSL 加密保障了应用程序与数据库集群之间的通信安全。",
		"ja": "SSL 暗号化により、アプリケーションとデータベースクラスタ間の通信が保護されます。",
		"de": "SSL-Verschlüsselung sichert die Kommunikation zwischen Anwendungen und dem Datenbankcluster.",
		"es": "El cifrado SSL protege la comunicación entre aplicaciones y el clúster de base de datos.",
		"fr": "Le chiffrement SSL sécurise la communication entre les applications et le cluster de base de données.",
		"pt": "A criptografia SSL protege a comunicação entre aplicações e o cluster de banco de dados.",
	},
	"recommendation": {
		"en": "Enable SSL for the PolarDB cluster.",
		"zh": "为 PolarDB 集群开启 SSL 加密。",
		"ja": "PolarDB クラスタで SSL を有効にします。",
		"de": "Aktivieren Sie SSL für den PolarDB-Cluster.",
		"es": "Habilite SSL para el clúster PolarDB.",
		"fr": "Activez SSL pour le cluster PolarDB.",
		"pt": "Habilite SSL para o cluster PolarDB.",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_compliant(resource) if {
	ssl := helpers.get_property(resource, "SSLEnabled", "Disable")
	ssl == "Enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SSLEnabled"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
