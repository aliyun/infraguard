package infraguard.rules.terraform.rds_public_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-public-access-check",
	"severity": "high",
	"name": {
		"en": "RDS Instance Public Access Check",
		"zh": "RDS 实例不配置公网地址",
		"ja": "RDS インスタンスのパブリックアクセスチェック",
		"de": "RDS-Instanz öffentlicher Zugriff Prüfung",
		"es": "Verificación de Acceso Público de Instancia RDS",
		"fr": "Vérification d'Accès Public d'Instance RDS",
		"pt": "Verificação de Acesso Público de Instância RDS"
	},
	"description": {
		"en": "RDS instances should not have security_ips configured to allow all source IPs (0.0.0.0/0).",
		"zh": "RDS 实例的 security_ips 不应配置为允许所有来源 IP（0.0.0.0/0）。",
		"ja": "RDS インスタンスの security_ips にすべてのソース IP（0.0.0.0/0）の許可を設定すべきではありません。",
		"de": "RDS-Instanzen sollten security_ips nicht so konfiguriert haben, dass alle Quell-IPs (0.0.0.0/0) erlaubt sind.",
		"es": "Las instancias RDS no deben tener security_ips configurado para permitir todas las IPs de origen (0.0.0.0/0).",
		"fr": "Les instances RDS ne doivent pas avoir security_ips configuré pour autoriser toutes les IP source (0.0.0.0/0).",
		"pt": "Instâncias RDS não devem ter security_ips configurado para permitir todos os IPs de origem (0.0.0.0/0)."
	},
	"reason": {
		"en": "The RDS instance security_ips contains 0.0.0.0/0, which exposes the database to security risks from the internet.",
		"zh": "RDS 实例的 security_ips 包含 0.0.0.0/0，使数据库暴露于来自互联网的安全风险。",
		"ja": "RDS インスタンスの security_ips に 0.0.0.0/0 が含まれているため、データベースがインターネットからのセキュリティリスクにさらされます。",
		"de": "Die RDS-Instanz security_ips enthält 0.0.0.0/0, was die Datenbank Sicherheitsrisiken aus dem Internet aussetzt.",
		"es": "La instancia RDS security_ips contiene 0.0.0.0/0, lo que expone la base de datos a riesgos de seguridad de internet.",
		"fr": "L'instance RDS security_ips contient 0.0.0.0/0, ce qui expose la base de données aux risques de sécurité d'Internet.",
		"pt": "A instância RDS security_ips contém 0.0.0.0/0, o que expõe o banco de dados a riscos de segurança da internet."
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
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

has_public_access(resource) if {
	security_ips := tf.get_attribute(resource, "security_ips", [])
	some ip in security_ips
	ip == "0.0.0.0/0"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	has_public_access(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
