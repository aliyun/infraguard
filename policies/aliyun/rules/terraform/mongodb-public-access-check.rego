package infraguard.rules.terraform.mongodb_public_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-public-access-check",
	"severity": "high",
	"name": {
		"en": "MongoDB Instance Public Access Check",
		"zh": "MongoDB 实例 IP 白名单禁止设置为全网段",
		"ja": "MongoDB ホワイトリストインターネット制限",
		"de": "MongoDB-Whitelist Internet-Einschränkung",
		"es": "Restricción de Internet de Lista Blanca MongoDB",
		"fr": "Restriction Internet de Liste Blanche MongoDB",
		"pt": "Restrição de Internet da Lista Branca MongoDB"
	},
	"description": {
		"en": "MongoDB instance security IP list should not contain 0.0.0.0/0 which allows access from any IP.",
		"zh": "MongoDB 实例的安全 IP 白名单不应包含 0.0.0.0/0（允许所有 IP 访问）。",
		"ja": "MongoDB セキュリティ IP ホワイトリストに 0.0.0.0/0 が含まれていないことを確認します。",
		"de": "Stellt sicher, dass MongoDB-Sicherheits-IP-Whitelists 0.0.0.0/0 nicht enthalten.",
		"es": "Garantiza que las listas blancas de IP de seguridad MongoDB no contengan 0.0.0.0/0.",
		"fr": "Garantit que les listes blanches d'IP de sécurité MongoDB ne contiennent pas 0.0.0.0/0.",
		"pt": "Garante que as listas brancas de IP de segurança MongoDB não contenham 0.0.0.0/0."
	},
	"reason": {
		"en": "The MongoDB instance security_ip_list contains 0.0.0.0/0, allowing access from any IP.",
		"zh": "MongoDB 实例的 security_ip_list 包含 0.0.0.0/0，允许任何 IP 访问。",
		"ja": "オープンな MongoDB ホワイトリストは、インターネット経由で機密データへの無制限アクセスを許可します。",
		"de": "Eine offene MongoDB-Whitelist erlaubt uneingeschränkten Zugriff auf sensible Daten über das Internet.",
		"es": "Una lista blanca MongoDB abierta permite acceso sin restricciones a datos sensibles a través de Internet.",
		"fr": "Une liste blanche MongoDB ouverte permet un accès sans restriction aux données sensibles via Internet.",
		"pt": "Uma lista branca MongoDB aberta permite acesso irrestrito a dados sensíveis pela Internet."
	},
	"recommendation": {
		"en": "Remove 0.0.0.0/0 from security_ip_list and use specific trusted IP ranges.",
		"zh": "从 security_ip_list 中移除 0.0.0.0/0，并使用特定的可信 IP 范围。",
		"ja": "MongoDB ホワイトリストを信頼できる IP 範囲に制限します。",
		"de": "Beschränken Sie die MongoDB-Whitelist auf vertrauenswürdige IP-Bereiche.",
		"es": "Restrinja la lista blanca MongoDB a rangos de IP confiables.",
		"fr": "Restreignez la liste blanche MongoDB aux plages d'IP de confiance.",
		"pt": "Restrinja a lista branca MongoDB a intervalos de IP confiáveis."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

has_public_access(resource) if {
	security_ips := tf.get_attribute(resource, "security_ip_list", [])
	some ip in security_ips
	ip == "0.0.0.0/0"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	has_public_access(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
