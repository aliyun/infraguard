package infraguard.rules.terraform.redis_instance_no_public_ip

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "redis-instance-no-public-ip",
	"severity": "medium",
	"name": {
		"en": "Redis Instance No Public IP",
		"zh": "Redis 实例未设置公网 IP",
		"ja": "Redis インスタンスにパブリック IP なし",
		"de": "Redis-Instanz ohne öffentliche IP",
		"es": "Instancia Redis Sin IP Pública",
		"fr": "Instance Redis Sans IP Publique",
		"pt": "Instância Redis Sem IP Público"
	},
	"description": {
		"en": "Ensures Redis instance does not have public IP assigned.",
		"zh": "确保 Redis 实例未设置公网 IP。",
		"ja": "Redis インスタンスにパブリック IP が割り当てられていないことを確認します。",
		"de": "Stellt sicher, dass der Redis-Instanz keine öffentliche IP zugewiesen ist.",
		"es": "Garantiza que la instancia Redis no tenga una IP pública asignada.",
		"fr": "Garantit que l'instance Redis n'a pas d'IP publique assignée.",
		"pt": "Garante que a instância Redis não tenha IP público atribuído."
	},
	"reason": {
		"en": "Public IP exposes Redis instance to internet attacks.",
		"zh": "公网 IP 使 Redis 实例暴露于互联网攻击。",
		"ja": "パブリック IP により、Redis インスタンスがインターネット攻撃にさらされます。",
		"de": "Öffentliche IP setzt die Redis-Instanz Internetangriffen aus.",
		"es": "La IP pública expone la instancia Redis a ataques de internet.",
		"fr": "L'IP publique expose l'instance Redis aux attaques Internet.",
		"pt": "O IP público expõe a instância Redis a ataques da internet."
	},
	"recommendation": {
		"en": "Set enable_public to false or remove it from the Redis instance configuration.",
		"zh": "将 enable_public 设置为 false 或从 Redis 实例配置中移除。",
		"ja": "Redis インスタンス設定で enable_public を false に設定するか削除します。",
		"de": "Setzen Sie enable_public auf false oder entfernen Sie es aus der Redis-Instanz-Konfiguration.",
		"es": "Configure enable_public como false o elimínelo de la configuración de la instancia Redis.",
		"fr": "Définissez enable_public sur false ou supprimez-le de la configuration de l'instance Redis.",
		"pt": "Defina enable_public como false ou remova-o da configuração da instância Redis."
	},
	"resource_types": ["alicloud_kvstore_instance"],
	"iac_type": "terraform"
}

has_public_ip(resource) if {
	enable_public := tf.get_attribute(resource, "enable_public", false)
	enable_public == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kvstore_instance")
	has_public_ip(resource)
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
