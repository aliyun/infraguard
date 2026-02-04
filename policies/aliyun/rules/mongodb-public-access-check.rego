package infraguard.rules.aliyun.mongodb_public_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "mongodb-public-access-check",
	"severity": "high",
	"name": {
		"en": "MongoDB Whitelist Internet Restriction",
		"zh": "MongoDB 白名单禁用公网开放",
		"ja": "MongoDB ホワイトリストインターネット制限",
		"de": "MongoDB-Whitelist Internet-Einschränkung",
		"es": "Restricción de Internet de Lista Blanca MongoDB",
		"fr": "Restriction Internet de Liste Blanche MongoDB",
		"pt": "Restrição de Internet da Lista Branca MongoDB"
	},
	"description": {
		"en": "Ensures MongoDB security IP whitelists do not contain 0.0.0.0/0.",
		"zh": "确保 MongoDB 安全 IP 白名单中不包含 0.0.0.0/0。",
		"ja": "MongoDB セキュリティ IP ホワイトリストに 0.0.0.0/0 が含まれていないことを確認します。",
		"de": "Stellt sicher, dass MongoDB-Sicherheits-IP-Whitelists 0.0.0.0/0 nicht enthalten.",
		"es": "Garantiza que las listas blancas de IP de seguridad MongoDB no contengan 0.0.0.0/0.",
		"fr": "Garantit que les listes blanches d'IP de sécurité MongoDB ne contiennent pas 0.0.0.0/0.",
		"pt": "Garante que as listas brancas de IP de segurança MongoDB não contenham 0.0.0.0/0."
	},
	"reason": {
		"en": "An open MongoDB whitelist allows unrestricted access to sensitive data over the internet.",
		"zh": "开放的 MongoDB 白名单允许通过互联网无限制地访问敏感数据。",
		"ja": "オープンな MongoDB ホワイトリストは、インターネット経由で機密データへの無制限アクセスを許可します。",
		"de": "Eine offene MongoDB-Whitelist erlaubt uneingeschränkten Zugriff auf sensible Daten über das Internet.",
		"es": "Una lista blanca MongoDB abierta permite acceso sin restricciones a datos sensibles a través de Internet.",
		"fr": "Une liste blanche MongoDB ouverte permet un accès sans restriction aux données sensibles via Internet.",
		"pt": "Uma lista branca MongoDB aberta permite acesso irrestrito a dados sensíveis pela Internet."
	},
	"recommendation": {
		"en": "Restrict the MongoDB whitelist to trusted IP ranges.",
		"zh": "将 MongoDB 白名单限制在可信 IP 范围内。",
		"ja": "MongoDB ホワイトリストを信頼できる IP 範囲に制限します。",
		"de": "Beschränken Sie die MongoDB-Whitelist auf vertrauenswürdige IP-Bereiche.",
		"es": "Restrinja la lista blanca MongoDB a rangos de IP confiables.",
		"fr": "Restreignez la liste blanche MongoDB aux plages d'IP de confiance.",
		"pt": "Restrinja a lista branca MongoDB a intervalos de IP confiáveis."
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"]
}

is_compliant(resource) if {
	whitelist_str := helpers.get_property(resource, "SecurityIPArray", "")
	whitelist := split(whitelist_str, ",")
	not has_public_ip(whitelist)
}

has_public_ip(whitelist) if {
	some ip in whitelist
	helpers.is_public_cidr(trim_space(ip))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPArray"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
