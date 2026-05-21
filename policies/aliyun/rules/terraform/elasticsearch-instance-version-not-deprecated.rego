package infraguard.rules.terraform.elasticsearch_instance_version_not_deprecated

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "elasticsearch-instance-version-not-deprecated",
	"severity": "high",
	"name": {"en": "Elasticsearch Instance Does Not Use Deprecated Version", "zh": "未使用不推荐的 Elasticsearch 实例版本", "ja": "Elasticsearch インスタンスが非推奨バージョンを使用していない", "de": "Elasticsearch-Instanz verwendet keine veraltete Version", "es": "La Instancia de Elasticsearch No Usa Versión Obsoleta", "fr": "L'Instance Elasticsearch N'Utilise Pas de Version Obsolète", "pt": "A Instância do Elasticsearch Não Usa Versão Obsoleta"},
	"description": {"en": "Ensures that Elasticsearch instances are not using deprecated or EOL versions.", "zh": "Elasticsearch 实例所使用的版本未在参数指定的不推荐版本范围内，视为合规。", "ja": "Elasticsearch インスタンスが非推奨または EOL バージョンを使用していないことを確認します。", "de": "Stellt sicher, dass Elasticsearch-Instanzen keine veralteten oder EOL-Versionen verwenden.", "es": "Garantiza que las instancias de Elasticsearch no estén usando versiones obsoletas o EOL.", "fr": "Garantit que les instances Elasticsearch n'utilisent pas de versions obsolètes ou EOL.", "pt": "Garante que as instâncias do Elasticsearch não estejam usando versões obsoletas ou EOL."},
	"reason": {"en": "Using deprecated Elasticsearch versions may have security vulnerabilities and lack support.", "zh": "使用不推荐的 Elasticsearch 版本可能存在安全漏洞且缺乏支持。", "ja": "非推奨の Elasticsearch バージョンを使用すると、セキュリティの脆弱性があり、サポートが不足している可能性があります。", "de": "Die Verwendung veralteter Elasticsearch-Versionen kann Sicherheitslücken haben und Unterstützung fehlen.", "es": "Usar versiones obsoletas de Elasticsearch puede tener vulnerabilidades de seguridad y carecer de soporte.", "fr": "L'utilisation de versions obsolètes d'Elasticsearch peut présenter des vulnérabilités de sécurité et manquer de support.", "pt": "Usar versões obsoletas do Elasticsearch pode ter vulnerabilidades de segurança e falta de suporte."},
	"recommendation": {"en": "Upgrade to a supported Elasticsearch version.", "zh": "请升级到支持的 Elasticsearch 版本。", "ja": "サポートされている Elasticsearch バージョンにアップグレードします。", "de": "Aktualisieren Sie auf eine unterstützte Elasticsearch-Version.", "es": "Actualice a una versión de Elasticsearch compatible.", "fr": "Mettez à niveau vers une version Elasticsearch prise en charge.", "pt": "Atualize para uma versão do Elasticsearch suportada."},
	"resource_types": ["alicloud_elasticsearch_instance"],
	"iac_type": "terraform"
}

default_deprecated_versions := ["5.5.3", "5.6.16", "6.3", "6.7", "7.0"]

deprecated_versions := versions if {
	params := object.get(input, "rule_parameters", {})
	versions := object.get(params, "deprecated_versions", default_deprecated_versions)
	versions != ""
} else := default_deprecated_versions

is_deprecated_version(version) if {
	some deprecated in deprecated_versions
	startswith(version, deprecated)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_elasticsearch_instance")
	version := tf.get_attribute(resource, "version", "")
	not tf.is_unknown(version)
	is_deprecated_version(version)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_elasticsearch_instance.%s", [name]),
		"violation_path": ["version"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
