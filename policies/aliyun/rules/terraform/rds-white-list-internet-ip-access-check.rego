package infraguard.rules.terraform.rds_white_list_internet_ip_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-white-list-internet-ip-access-check",
	"severity": "high",
	"name": {
		"en": "RDS Whitelist Internet Restriction",
		"zh": "RDS 白名单禁用公网开放",
		"ja": "RDS ホワイトリストインターネット制限",
		"de": "RDS-Whitelist Internet-Einschränkung",
		"es": "Restricción de Internet de Lista Blanca RDS",
		"fr": "Restriction Internet de Liste Blanche RDS",
		"pt": "Restrição de Internet da Lista Branca RDS"
	},
	"description": {
		"en": "Ensures RDS security IP whitelists do not contain 0.0.0.0/0 or 0.0.0.0.",
		"zh": "确保 RDS 安全 IP 白名单中不包含 0.0.0.0/0 或 0.0.0.0。",
		"ja": "RDS セキュリティ IP ホワイトリストに 0.0.0.0/0 または 0.0.0.0 が含まれていないことを確認します。",
		"de": "Stellt sicher, dass RDS-Sicherheits-IP-Whitelists 0.0.0.0/0 oder 0.0.0.0 nicht enthalten.",
		"es": "Garantiza que las listas blancas de IP de seguridad RDS no contengan 0.0.0.0/0 o 0.0.0.0.",
		"fr": "Garantit que les listes blanches d'IP de sécurité RDS ne contiennent pas 0.0.0.0/0 ou 0.0.0.0.",
		"pt": "Garante que as listas brancas de IP de segurança RDS não contenham 0.0.0.0/0 ou 0.0.0.0."
	},
	"reason": {
		"en": "Allowing 0.0.0.0/0 in the whitelist exposes the database to all public internet traffic.",
		"zh": "在白名单中允许 0.0.0.0/0 会使数据库暴露给所有的公网流量。",
		"ja": "ホワイトリストで 0.0.0.0/0 を許可すると、データベースがすべてのパブリックインターネットトラフィックにさらされます。",
		"de": "Das Zulassen von 0.0.0.0/0 in der Whitelist setzt die Datenbank dem gesamten öffentlichen Internetverkehr aus.",
		"es": "Permitir 0.0.0.0/0 en la lista blanca expone la base de datos a todo el tráfico público de Internet.",
		"fr": "Autoriser 0.0.0.0/0 dans la liste blanche expose la base de données à tout le trafic Internet public.",
		"pt": "Permitir 0.0.0.0/0 na lista branca expõe o banco de dados a todo o tráfego público da Internet."
	},
	"recommendation": {
		"en": "Remove 0.0.0.0/0 and 0.0.0.0 from security_ips and use specific trusted IPs.",
		"zh": "从 security_ips 中移除 0.0.0.0/0 和 0.0.0.0，并使用特定的可信 IP。",
		"ja": "security_ips から 0.0.0.0/0 と 0.0.0.0 を削除し、特定の信頼できる IP を使用します。",
		"de": "Entfernen Sie 0.0.0.0/0 und 0.0.0.0 aus security_ips und verwenden Sie spezifische vertrauenswürdige IPs.",
		"es": "Elimine 0.0.0.0/0 y 0.0.0.0 de security_ips y use IPs confiables específicas.",
		"fr": "Supprimez 0.0.0.0/0 et 0.0.0.0 de security_ips et utilisez des IP de confiance spécifiques.",
		"pt": "Remova 0.0.0.0/0 e 0.0.0.0 de security_ips e use IPs confiáveis específicos."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

has_open_whitelist(resource) if {
	security_ips := tf.get_attribute(resource, "security_ips", [])
	some ip in security_ips
	ip == "0.0.0.0/0"
}

has_open_whitelist(resource) if {
	security_ips := tf.get_attribute(resource, "security_ips", [])
	some ip in security_ips
	ip == "0.0.0.0"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	has_open_whitelist(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
