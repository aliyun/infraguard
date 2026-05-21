package infraguard.rules.terraform.polardb_revision_version_used_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "polardb-revision-version-used-check",
	"severity": "medium",
	"name": {
		"en": "PolarDB Revision Version Used Check",
		"zh": "使用稳定内核版本的 PolarDB 集群",
		"ja": "PolarDB リビジョンバージョン使用チェック",
		"de": "PolarDB Revisionsversion Verwendungsprüfung",
		"es": "Verificación de Versión de Revisión PolarDB Utilizada",
		"fr": "Vérification de la Version de Révision PolarDB Utilisée",
		"pt": "Verificação de Versão de Revisão PolarDB Utilizada"
	},
	"description": {
		"en": "Ensures PolarDB cluster has db_version explicitly set for stable kernel version.",
		"zh": "确保 PolarDB 集群明确设置了 db_version 以使用稳定内核版本。",
		"ja": "PolarDB クラスターが安定したカーネルバージョン用に db_version を明示的に設定していることを確認します。",
		"de": "Stellt sicher, dass der PolarDB-Cluster db_version für eine stabile Kernel-Version explizit gesetzt hat.",
		"es": "Garantiza que el clúster PolarDB tenga db_version configurado explícitamente para una versión de kernel estable.",
		"fr": "Garantit que le cluster PolarDB a db_version explicitement défini pour une version de noyau stable.",
		"pt": "Garante que o cluster PolarDB tenha db_version explicitamente definido para uma versão de kernel estável."
	},
	"reason": {
		"en": "Using stable kernel version ensures better reliability and security.",
		"zh": "使用稳定内核版本确保更好的可靠性和安全性。",
		"ja": "安定したカーネルバージョンを使用することで、より優れた信頼性とセキュリティが確保されます。",
		"de": "Die Verwendung einer stabilen Kernel-Version gewährleistet bessere Zuverlässigkeit und Sicherheit.",
		"es": "Usar una versión de kernel estable garantiza mejor confiabilidad y seguridad.",
		"fr": "L'utilisation d'une version de noyau stable garantit une meilleure fiabilité et sécurité.",
		"pt": "Usar uma versão de kernel estável garante melhor confiabilidade e segurança."
	},
	"recommendation": {
		"en": "Set db_version explicitly for the PolarDB cluster to use a stable kernel version.",
		"zh": "为 PolarDB 集群明确设置 db_version 以使用稳定内核版本。",
		"ja": "PolarDB クラスターの db_version を明示的に設定して安定したカーネルバージョンを使用します。",
		"de": "Setzen Sie db_version explizit für den PolarDB-Cluster, um eine stabile Kernel-Version zu verwenden.",
		"es": "Configure db_version explícitamente para el clúster PolarDB para usar una versión de kernel estable.",
		"fr": "Définissez db_version explicitement pour le cluster PolarDB pour utiliser une version de noyau stable.",
		"pt": "Defina db_version explicitamente para o cluster PolarDB para usar uma versão de kernel estável."
	},
	"resource_types": ["alicloud_polardb_cluster"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_polardb_cluster")
	db_version := tf.get_attribute(resource, "db_version", "")
	db_version == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_polardb_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
