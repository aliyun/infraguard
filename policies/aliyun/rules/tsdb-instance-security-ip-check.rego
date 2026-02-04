package infraguard.rules.aliyun.tsdb_instance_security_ip_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "tsdb-instance-security-ip-check",
	"severity": "high",
	"name": {
		"en": "TSDB Instance Does Not Allow Any IP Access",
		"zh": "TSDB 实例安全白名单检测",
		"ja": "TSDB インスタンスが任意の IP アクセスを許可しない",
		"de": "TSDB-Instanz erlaubt keinen IP-Zugriff",
		"es": "La Instancia TSDB No Permite Acceso de Cualquier IP",
		"fr": "L'Instance TSDB N'autorise Pas l'Accès IP",
		"pt": "Instância TSDB Não Permite Acesso de Qualquer IP"
	},
	"description": {
		"en": "Ensures that TSDB instances do not have security whitelists that allow all IPs.",
		"zh": "TSDB 实例没有开启任意 IP 访问，视为合规。",
		"ja": "TSDB インスタンスにすべての IP を許可するセキュリティホワイトリストがないことを確認します。",
		"de": "Stellt sicher, dass TSDB-Instanzen keine Sicherheits-Whitelists haben, die alle IPs erlauben.",
		"es": "Garantiza que las instancias TSDB no tengan listas blancas de seguridad que permitan todas las IPs.",
		"fr": "Garantit que les instances TSDB n'ont pas de listes blanches de sécurité qui autorisent toutes les IP.",
		"pt": "Garante que as instâncias TSDB não tenham listas brancas de segurança que permitam todos os IPs."
	},
	"reason": {
		"en": "TSDB instance allows access from any IP address, which is a security risk.",
		"zh": "TSDB 实例开启任意 IP 访问，存在安全风险。",
		"ja": "TSDB インスタンスが任意の IP アドレスからのアクセスを許可しており、セキュリティリスクがあります。",
		"de": "TSDB-Instanz erlaubt Zugriff von jeder IP-Adresse, was ein Sicherheitsrisiko darstellt.",
		"es": "La instancia TSDB permite el acceso desde cualquier dirección IP, lo cual es un riesgo de seguridad.",
		"fr": "L'instance TSDB autorise l'accès depuis n'importe quelle adresse IP, ce qui constitue un risque de sécurité.",
		"pt": "A instância TSDB permite acesso de qualquer endereço IP, o que é um risco de segurança."
	},
	"recommendation": {
		"en": "Configure security whitelist to restrict access to specific IPs.",
		"zh": "请配置安全白名单以限制特定 IP 访问。",
		"ja": "特定の IP へのアクセスを制限するためにセキュリティホワイトリストを設定します。",
		"de": "Konfigurieren Sie die Sicherheits-Whitelist, um den Zugriff auf bestimmte IPs einzuschränken.",
		"es": "Configure la lista blanca de seguridad para restringir el acceso a IPs específicas.",
		"fr": "Configurez la liste blanche de sécurité pour restreindre l'accès à des IP spécifiques.",
		"pt": "Configure a lista branca de segurança para restringir o acesso a IPs específicos."
	},
	"resource_types": ["ALIYUN::TSDB::HiTSDBInstance"]
}

# Check if whitelist allows any IP
allows_any_ip(whitelist) if {
	count(whitelist) == 1
	whitelist[0] == "0.0.0.0/0"
}

allows_any_ip(whitelist) if {
	count(whitelist) == 1
	whitelist[0] == "0.0.0.0"
}

allows_any_ip(whitelist) := false if {
	count(whitelist) != 1
}

allows_any_ip(whitelist) := false if {
	count(whitelist) == 1
	whitelist[0] != "0.0.0.0/0"
	whitelist[0] != "0.0.0.0"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::TSDB::HiTSDBInstance")

	whitelist := resource.Properties.SecurityIpList
	allows_any_ip(whitelist)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIpList"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
