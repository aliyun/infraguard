package infraguard.rules.terraform.rds_public_connection_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-public-connection-and-any-ip-access-check",
	"severity": "high",
	"name": {
		"en": "RDS Public Connection and Any IP Access Check",
		"zh": "开启公网 IP 的 RDS 实例白名单未对所有来源开放",
		"ja": "RDS のパブリック接続および任意の IP アクセスチェック",
		"de": "RDS öffentliche Verbindung und beliebige IP-Zugriff-Prüfung",
		"es": "Verificación de Conexión Pública y Acceso de Cualquier IP de RDS",
		"fr": "Vérification de Connexion Publique et d'Accès de N'importe Quelle IP RDS",
		"pt": "Verificação de Conexão Pública e Acesso de Qualquer IP RDS"
	},
	"description": {
		"en": "Ensures that RDS instances do not have a completely unrestricted security IP whitelist.",
		"zh": "确保 RDS 实例的安全白名单未设置为完全不受限制。",
		"ja": "RDS インスタンスのセキュリティ IP ホワイトリストが完全に無制限ではないことを確認します。",
		"de": "Stellt sicher, dass RDS-Instanzen keine völlig uneingeschränkte Sicherheits-IP-Whitelist haben.",
		"es": "Garantiza que las instancias RDS no tengan una lista blanca de IP de seguridad completamente sin restricciones.",
		"fr": "Garantit que les instances RDS n'ont pas une liste blanche d'IP de sécurité complètement non restreinte.",
		"pt": "Garante que instâncias RDS não tenham uma lista branca de IP de segurança completamente irrestrita."
	},
	"reason": {
		"en": "An open whitelist combined with a public connection exposes the database to the internet, creating a high security risk.",
		"zh": "公网连接配合开放白名单会将数据库暴露在互联网上，造成极高的安全风险。",
		"ja": "オープンホワイトリストとパブリック接続の組み合わせにより、データベースがインターネットに公開され、高いセキュリティリスクが生じます。",
		"de": "Eine offene Whitelist in Kombination mit einer öffentlichen Verbindung setzt die Datenbank dem Internet aus und schafft ein hohes Sicherheitsrisiko.",
		"es": "Una lista blanca abierta combinada con una conexión pública expone la base de datos a internet, creando un alto riesgo de seguridad.",
		"fr": "Une liste blanche ouverte combinée à une connexion publique expose la base de données à Internet, créant un risque de sécurité élevé.",
		"pt": "Uma lista branca aberta combinada com uma conexão pública expõe o banco de dados à internet, criando um alto risco de segurança."
	},
	"recommendation": {
		"en": "Restrict security_ips to specific trusted IP ranges instead of allowing all IPs.",
		"zh": "将 security_ips 限制为特定的可信 IP 范围，而不是允许所有 IP。",
		"ja": "security_ips をすべての IP を許可するのではなく、特定の信頼できる IP 範囲に制限します。",
		"de": "Beschränken Sie security_ips auf spezifische vertrauenswürdige IP-Bereiche, anstatt alle IPs zuzulassen.",
		"es": "Restrinja security_ips a rangos de IP confiables específicos en lugar de permitir todas las IPs.",
		"fr": "Restreignez security_ips à des plages d'IP de confiance spécifiques au lieu d'autoriser toutes les IP.",
		"pt": "Restrinja security_ips a faixas de IP confiáveis específicas em vez de permitir todos os IPs."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

is_fully_open(resource) if {
	security_ips := tf.get_attribute(resource, "security_ips", [])
	count(security_ips) == 1
	security_ips[0] == "0.0.0.0/0"
}

is_fully_open(resource) if {
	security_ips := tf.get_attribute(resource, "security_ips", [])
	count(security_ips) == 1
	security_ips[0] == "0.0.0.0"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	is_fully_open(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
