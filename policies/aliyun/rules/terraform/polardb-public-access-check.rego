package infraguard.rules.terraform.polardb_public_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "polardb-public-access-check",
	"severity": "high",
	"name": {
		"en": "PolarDB Public Access Check",
		"zh": "PolarDB 实例 IP 白名单禁止设置为全网段",
		"ja": "PolarDB パブリックアクセスチェック",
		"de": "PolarDB Öffentlicher Zugriffsprüfung",
		"es": "Verificación de Acceso Público de PolarDB",
		"fr": "Vérification d'Accès Public PolarDB",
		"pt": "Verificação de Acesso Público do PolarDB"
	},
	"description": {
		"en": "Ensures PolarDB security_ips is not set to allow all source IPs (0.0.0.0/0).",
		"zh": "确保 PolarDB 实例的 security_ips 未设置为允许所有来源 IP（0.0.0.0/0）。",
		"ja": "PolarDB の security_ips にすべてのソース IP（0.0.0.0/0）の許可を設定すべきではありません。",
		"de": "Stellt sicher, dass PolarDB security_ips nicht auf 0.0.0.0/0 gesetzt ist.",
		"es": "Garantiza que security_ips de PolarDB no esté establecida en 0.0.0.0/0.",
		"fr": "Garantit que security_ips PolarDB n'est pas définie sur 0.0.0.0/0.",
		"pt": "Garante que security_ips do PolarDB não esteja definida como 0.0.0.0/0."
	},
	"reason": {
		"en": "The PolarDB cluster security_ips contains 0.0.0.0/0, which allows access from any IP and is a severe security risk.",
		"zh": "PolarDB 集群的 security_ips 包含 0.0.0.0/0，允许任何 IP 访问，这是一个严重的安全风险。",
		"ja": "PolarDB クラスタの security_ips に 0.0.0.0/0 が含まれているため、任意の IP からのアクセスが許可され、深刻なセキュリティリスクとなります。",
		"de": "Die PolarDB-Cluster security_ips enthält 0.0.0.0/0, was Zugriff von jeder IP erlaubt und ein schwerwiegendes Sicherheitsrisiko darstellt.",
		"es": "El security_ips del clúster PolarDB contiene 0.0.0.0/0, lo que permite el acceso desde cualquier IP y es un riesgo de seguridad grave.",
		"fr": "Le security_ips du cluster PolarDB contient 0.0.0.0/0, ce qui autorise l'accès depuis n'importe quelle IP et constitue un risque de sécurité grave.",
		"pt": "O security_ips do cluster PolarDB contém 0.0.0.0/0, o que permite acesso de qualquer IP e é um risco de segurança grave."
	},
	"recommendation": {
		"en": "Remove 0.0.0.0/0 from security_ips and use specific trusted IP ranges.",
		"zh": "从 security_ips 中移除 0.0.0.0/0，并使用特定的可信 IP 范围。",
		"ja": "security_ips から 0.0.0.0/0 を削除し、特定の信頼できる IP 範囲を使用します。",
		"de": "Entfernen Sie 0.0.0.0/0 aus security_ips und verwenden Sie spezifische vertrauenswürdige IP-Bereiche.",
		"es": "Elimine 0.0.0.0/0 de security_ips y use rangos de IP confiables específicos.",
		"fr": "Supprimez 0.0.0.0/0 de security_ips et utilisez des plages d'IP de confiance spécifiques.",
		"pt": "Remova 0.0.0.0/0 de security_ips e use faixas de IP confiáveis específicas."
	},
	"resource_types": ["alicloud_polardb_cluster"],
	"iac_type": "terraform"
}

has_public_access(resource) if {
	security_ips := tf.get_attribute(resource, "security_ips", [])
	some ip in security_ips
	ip == "0.0.0.0/0"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_polardb_cluster")
	has_public_access(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_polardb_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
