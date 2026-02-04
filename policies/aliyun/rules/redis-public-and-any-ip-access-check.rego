package infraguard.rules.aliyun.redis_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "redis-public-and-any-ip-access-check",
	"name": {
		"en": "Redis Public and Any IP Access Check",
		"zh": "Redis 实例不开启公网或安全白名单不设置为允许任意来源访问",
		"ja": "Redis のパブリックおよび任意の IP アクセスチェック",
		"de": "Redis öffentlicher und beliebiger IP-Zugriff-Prüfung",
		"es": "Verificación de Acceso Público y de Cualquier IP de Redis",
		"fr": "Vérification d'Accès Public et de N'importe Quelle IP Redis",
		"pt": "Verificação de Acesso Público e de Qualquer IP do Redis",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Redis instances do not have public access enabled or an open whitelist.",
		"zh": "确保 Redis 实例未开启公网访问，或者白名单未设置为对所有 IP 开放。",
		"ja": "Redis インスタンスでパブリックアクセスが有効になっていないか、オープンホワイトリストが設定されていないことを確認します。",
		"de": "Stellt sicher, dass Redis-Instanzen keinen öffentlichen Zugriff aktiviert haben oder eine offene Whitelist haben.",
		"es": "Garantiza que las instancias Redis no tengan acceso público habilitado o una lista blanca abierta.",
		"fr": "Garantit que les instances Redis n'ont pas d'accès public activé ou une liste blanche ouverte.",
		"pt": "Garante que as instâncias Redis não tenham acesso público habilitado ou uma lista branca aberta."
	},
	"reason": {
		"en": "Public access to Redis is a severe security risk, as it is often targets for brute force attacks and data theft.",
		"zh": "Redis 的公网访问是一个严重的安全风险，因为它经常成为暴力破解攻击和数据窃取的方目标。",
		"ja": "Redis へのパブリックアクセスは重大なセキュリティリスクであり、ブルートフォース攻撃やデータ窃取の標的となることがよくあります。",
		"de": "Öffentlicher Zugriff auf Redis ist ein schwerwiegendes Sicherheitsrisiko, da es häufig Ziel von Brute-Force-Angriffen und Datendiebstahl ist.",
		"es": "El acceso público a Redis es un riesgo de seguridad severo, ya que a menudo es objetivo de ataques de fuerza bruta y robo de datos.",
		"fr": "L'accès public à Redis est un risque de sécurité grave, car il est souvent la cible d'attaques par force brute et de vol de données.",
		"pt": "O acesso público ao Redis é um risco de segurança severo, pois frequentemente é alvo de ataques de força bruta e roubo de dados.",
	},
	"recommendation": {
		"en": "Disable public connection for the Redis instance and restrict access via IP whitelists.",
		"zh": "禁用 Redis 实例的公网连接，并通过 IP 白名单限制访问。",
		"ja": "Redis インスタンスのパブリック接続を無効にし、IP ホワイトリストを介してアクセスを制限します。",
		"de": "Deaktivieren Sie die öffentliche Verbindung für die Redis-Instanz und beschränken Sie den Zugriff über IP-Whitelists.",
		"es": "Deshabilite la conexión pública para la instancia Redis y restrinja el acceso mediante listas blancas de IP.",
		"fr": "Désactivez la connexion publique pour l'instance Redis et restreignez l'accès via les listes blanches IP.",
		"pt": "Desabilite a conexão pública para a instância Redis e restrinja o acesso via listas brancas de IP.",
	},
	"resource_types": ["ALIYUN::REDIS::Instance"],
}

is_compliant(resource) if {
	# Check Connections property
	connections := helpers.get_property(resource, "Connections", {})

	# It is compliant if PublicConnection is NOT present
	object.get(connections, "PublicConnection", null) == null
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Connections", "PublicConnection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
