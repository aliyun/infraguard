package infraguard.rules.aliyun.polardb_public_access_check

import rego.v1

import data.infraguard.helpers

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
		"en": "Ensures PolarDB IP whitelist is not set to 0.0.0.0/0.",
		"zh": "确保 PolarDB 实例 IP 白名单未设置为 0.0.0.0/0。",
		"ja": "PolarDB IP ホワイトリストが 0.0.0.0/0 に設定されていないことを確認します。",
		"de": "Stellt sicher, dass die PolarDB-IP-Whitelist nicht auf 0.0.0.0/0 gesetzt ist.",
		"es": "Garantiza que la lista blanca de IP de PolarDB no esté establecida en 0.0.0.0/0.",
		"fr": "Garantit que la liste blanche IP PolarDB n'est pas définie sur 0.0.0.0/0.",
		"pt": "Garante que a lista branca de IP do PolarDB não esteja definida como 0.0.0.0/0."
	},
	"reason": {
		"en": "Setting whitelist to 0.0.0.0/0 allows access from any IP, which is a severe security risk.",
		"zh": "将白名单设置为 0.0.0.0/0 允许任何 IP 访问，这是一个严重的安全风险。",
		"ja": "ホワイトリストを 0.0.0.0/0 に設定すると、任意の IP からのアクセスが許可され、深刻なセキュリティリスクとなります。",
		"de": "Das Setzen der Whitelist auf 0.0.0.0/0 erlaubt Zugriff von jeder IP, was ein schwerwiegendes Sicherheitsrisiko darstellt.",
		"es": "Establecer la lista blanca en 0.0.0.0/0 permite el acceso desde cualquier IP, lo que es un riesgo de seguridad grave.",
		"fr": "Définir la liste blanche sur 0.0.0.0/0 autorise l'accès depuis n'importe quelle IP, ce qui constitue un risque de sécurité grave.",
		"pt": "Definir a lista branca como 0.0.0.0/0 permite acesso de qualquer IP, o que é um risco de segurança grave."
	},
	"recommendation": {
		"en": "Configure IP whitelist to restrict access to specific IPs.",
		"zh": "配置 IP 白名单以限制特定 IP 访问。",
		"ja": "特定の IP へのアクセスを制限するように IP ホワイトリストを設定します。",
		"de": "Konfigurieren Sie die IP-Whitelist, um den Zugriff auf bestimmte IPs einzuschränken.",
		"es": "Configure la lista blanca de IP para restringir el acceso a IPs específicas.",
		"fr": "Configurez la liste blanche IP pour restreindre l'accès à des IP spécifiques.",
		"pt": "Configure a lista branca de IP para restringir o acesso a IPs específicos."
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"]
}

is_compliant(resource) if {
	whitelist := helpers.get_property(resource, "SecurityIPList", "")
	whitelist != "0.0.0.0/0"
}

is_compliant(resource) if {
	whitelist := helpers.get_property(resource, "SecurityIPList", "")
	not contains(whitelist, "0.0.0.0/0")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPList"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
