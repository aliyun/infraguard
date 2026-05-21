package infraguard.rules.terraform.oss_bucket_tls_version_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-tls-version-check",
	"severity": "medium",
	"name": {
		"en": "OSS Bucket TLS Version Check",
		"zh": "OSS 存储桶 TLS 版本检测",
		"ja": "OSS バケットの TLS バージョンチェック",
		"de": "OSS-Bucket TLS-Versionsprüfung",
		"es": "Verificación de Versión TLS de Bucket OSS",
		"fr": "Vérification de la Version TLS de Bucket OSS",
		"pt": "Verificação de Versão TLS de Bucket OSS"
	},
	"description": {
		"en": "Ensures OSS bucket has a policy set to enforce TLS requirements.",
		"zh": "确保 OSS 存储桶设置了策略以强制 TLS 要求。",
		"ja": "OSS バケットが安全な TLS バージョン（TLS 1.2 以上）を使用するように設定されていることを確認します。",
		"de": "Stellt sicher, dass der OSS-Bucket so konfiguriert ist, dass er eine sichere TLS-Version (TLS 1.2 oder höher) verwendet.",
		"es": "Garantiza que el bucket OSS esté configurado para usar una versión segura de TLS (TLS 1.2 o superior).",
		"fr": "Garantit que le bucket OSS est configuré pour utiliser une version sécurisée de TLS (TLS 1.2 ou supérieure).",
		"pt": "Garante que o bucket OSS esteja configurado para usar uma versão segura de TLS (TLS 1.2 ou superior)."
	},
	"reason": {
		"en": "The OSS bucket does not have a policy configured to enforce TLS.",
		"zh": "OSS 存储桶未配置策略以强制 TLS。",
		"ja": "古いバージョンの TLS にはセキュリティの脆弱性があります。新しいバージョンを使用することで、データ転送のセキュリティが確保されます。",
		"de": "Ältere Versionen von TLS haben Sicherheitslücken. Die Verwendung neuerer Versionen gewährleistet die Datentransportsicherheit.",
		"es": "Las versiones anteriores de TLS tienen vulnerabilidades de seguridad. El uso de versiones más nuevas garantiza la seguridad del transporte de datos.",
		"fr": "Les anciennes versions de TLS présentent des vulnérabilités de sécurité. L'utilisation de versions plus récentes assure la sécurité du transport des données.",
		"pt": "Versões antigas de TLS têm vulnerabilidades de segurança. O uso de versões mais recentes garante a segurança do transporte de dados."
	},
	"recommendation": {
		"en": "Set a bucket policy that enforces secure transport requirements.",
		"zh": "设置存储桶策略以强制安全传输要求。",
		"ja": "OSS バケットを設定して、すべてのリクエストに TLS 1.2 以上を要求します。",
		"de": "Konfigurieren Sie den OSS-Bucket so, dass TLS 1.2 oder höher für alle Anfragen erforderlich ist.",
		"es": "Configure el bucket OSS para requerir TLS 1.2 o superior para todas las solicitudes.",
		"fr": "Configurez le bucket OSS pour exiger TLS 1.2 ou supérieur pour toutes les requêtes.",
		"pt": "Configure o bucket OSS para exigir TLS 1.2 ou superior para todas as solicitações."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

has_policy(resource) if {
	policy_str := tf.get_attribute(resource, "policy", "")
	not tf.is_unknown(policy_str)
	policy_str != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	not has_policy(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_oss_bucket.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
