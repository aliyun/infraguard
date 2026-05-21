package infraguard.rules.terraform.redis_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-public-and-any-ip-access-check",
	"severity": "high",
	"name": {
		"en": "Redis Public and Any IP Access Check",
		"zh": "Redis 实例不开启公网或安全白名单不设置为允许任意来源访问",
		"ja": "Redis のパブリックおよび任意の IP アクセスチェック",
		"de": "Redis öffentlicher und beliebiger IP-Zugriff-Prüfung",
		"es": "Verificación de Acceso Público y de Cualquier IP de Redis",
		"fr": "Vérification d'Accès Public et de N'importe Quelle IP Redis",
		"pt": "Verificação de Acesso Público e de Qualquer IP do Redis"
	},
	"description": {
		"en": "Ensures that Redis instances do not have an open whitelist allowing access from any IP.",
		"zh": "确保 Redis 实例的白名单未设置为对所有 IP 开放。",
		"ja": "Redis インスタンスで任意の IP からのアクセスを許可するオープンホワイトリストが設定されていないことを確認します。",
		"de": "Stellt sicher, dass Redis-Instanzen keine offene Whitelist haben, die Zugriff von jeder IP erlaubt.",
		"es": "Garantiza que las instancias Redis no tengan una lista blanca abierta permitiendo acceso desde cualquier IP.",
		"fr": "Garantit que les instances Redis n'ont pas une liste blanche ouverte permettant l'accès depuis n'importe quelle IP.",
		"pt": "Garante que as instâncias Redis não tenham uma lista branca aberta permitindo acesso de qualquer IP."
	},
	"reason": {
		"en": "Public access to Redis is a severe security risk, as it is often targets for brute force attacks and data theft.",
		"zh": "Redis 的公网访问是一个严重的安全风险，因为它经常成为暴力破解攻击和数据窃取的目标。",
		"ja": "Redis へのパブリックアクセスは重大なセキュリティリスクであり、ブルートフォース攻撃やデータ窃取の標的となることがよくあります。",
		"de": "Öffentlicher Zugriff auf Redis ist ein schwerwiegendes Sicherheitsrisiko, da es häufig Ziel von Brute-Force-Angriffen und Datendiebstahl ist.",
		"es": "El acceso público a Redis es un riesgo de seguridad severo, ya que a menudo es objetivo de ataques de fuerza bruta y robo de datos.",
		"fr": "L'accès public à Redis est un risque de sécurité grave, car il est souvent la cible d'attaques par force brute et de vol de données.",
		"pt": "O acesso público ao Redis é um risco de segurança severo, pois frequentemente é alvo de ataques de força bruta e roubo de dados."
	},
	"recommendation": {
		"en": "Restrict security_ips to specific IP ranges instead of 0.0.0.0/0.",
		"zh": "将 security_ips 限制为特定 IP 范围，而不是 0.0.0.0/0。",
		"ja": "security_ips を 0.0.0.0/0 ではなく特定の IP 範囲に制限します。",
		"de": "Beschränken Sie security_ips auf bestimmte IP-Bereiche anstatt 0.0.0.0/0.",
		"es": "Restrinja security_ips a rangos de IP específicos en lugar de 0.0.0.0/0.",
		"fr": "Restreignez security_ips à des plages IP spécifiques au lieu de 0.0.0.0/0.",
		"pt": "Restrinja security_ips a faixas de IP específicas em vez de 0.0.0.0/0."
	},
	"resource_types": ["alicloud_kvstore_instance"],
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
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	has_open_whitelist(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kvstore_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
