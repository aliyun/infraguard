package infraguard.rules.aliyun.polardb_revision_version_used_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "polardb-revision-version-used-check",
	"name": {
		"en": "PolarDB Revision Version Used Check",
		"zh": "使用稳定内核版本的 PolarDB 集群",
		"ja": "PolarDB リビジョンバージョン使用チェック",
		"de": "PolarDB Revisionsversion Verwendungsprüfung",
		"es": "Verificación de Versión de Revisión PolarDB Utilizada",
		"fr": "Vérification de la Version de Révision PolarDB Utilisée",
		"pt": "Verificação de Versão de Revisão PolarDB Utilizada",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures PolarDB cluster is using a stable kernel revision version.",
		"zh": "确保 PolarDB 集群使用稳定内核版本。",
		"ja": "PolarDB クラスターが安定したカーネルリビジョンバージョンを使用していることを確認します。",
		"de": "Stellt sicher, dass der PolarDB-Cluster eine stabile Kernel-Revisionsversion verwendet.",
		"es": "Garantiza que el clúster PolarDB esté usando una versión de revisión de kernel estable.",
		"fr": "Garantit que le cluster PolarDB utilise une version de révision de noyau stable.",
		"pt": "Garante que o cluster PolarDB esteja usando uma versão de revisão de kernel estável.",
	},
	"reason": {
		"en": "Using stable kernel version ensures better reliability and security.",
		"zh": "使用稳定内核版本确保更好的可靠性和安全性。",
		"ja": "安定したカーネルバージョンを使用することで、より優れた信頼性とセキュリティが確保されます。",
		"de": "Die Verwendung einer stabilen Kernel-Version gewährleistet bessere Zuverlässigkeit und Sicherheit.",
		"es": "Usar una versión de kernel estable garantiza mejor confiabilidad y seguridad.",
		"fr": "L'utilisation d'une version de noyau stable garantit une meilleure fiabilité et sécurité.",
		"pt": "Usar uma versão de kernel estável garante melhor confiabilidade e segurança.",
	},
	"recommendation": {
		"en": "Use stable kernel version for the PolarDB cluster.",
		"zh": "为 PolarDB 集群使用稳定内核版本。",
		"ja": "PolarDB クラスターに安定したカーネルバージョンを使用します。",
		"de": "Verwenden Sie eine stabile Kernel-Version für den PolarDB-Cluster.",
		"es": "Use una versión de kernel estable para el clúster PolarDB.",
		"fr": "Utilisez une version de noyau stable pour le cluster PolarDB.",
		"pt": "Use uma versão de kernel estável para o cluster PolarDB.",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_compliant(resource) if {
	db_version := helpers.get_property(resource, "DBVersion", "")
	db_version != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DBVersion"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
