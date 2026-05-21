package infraguard.rules.terraform.tsdb_instance_security_ip_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Configure security_ip_list to restrict access to specific IPs instead of allowing all.",
		"zh": "配置 security_ip_list 以限制特定 IP 访问，而不是允许所有 IP。",
		"ja": "すべての IP を許可するのではなく、特定の IP へのアクセスを制限するように security_ip_list を設定します。",
		"de": "Konfigurieren Sie security_ip_list, um den Zugriff auf bestimmte IPs einzuschränken, anstatt alle zuzulassen.",
		"es": "Configure security_ip_list para restringir el acceso a IPs específicas en lugar de permitir todas.",
		"fr": "Configurez security_ip_list pour restreindre l'accès à des IP spécifiques au lieu d'autoriser toutes.",
		"pt": "Configure security_ip_list para restringir o acesso a IPs específicos em vez de permitir todos."
	},
	"resource_types": ["alicloud_tsdb_instance"],
	"iac_type": "terraform"
}

# Check if security_ip_list allows any IP
allows_any_ip(resource) if {
	ip_list := tf.get_attribute(resource, "security_ip_list", [])
	count(ip_list) == 1
	ip_list[0] in {"0.0.0.0/0", "0.0.0.0"}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_tsdb_instance")
	allows_any_ip(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_tsdb_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
