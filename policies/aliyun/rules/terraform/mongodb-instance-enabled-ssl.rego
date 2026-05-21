package infraguard.rules.terraform.mongodb_instance_enabled_ssl

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-instance-enabled-ssl",
	"severity": "medium",
	"name": {
		"en": "MongoDB Instance SSL Enabled",
		"zh": "MongoDB 实例开启 SSL 加密",
		"ja": "MongoDB インスタンス SSL 有効",
		"de": "MongoDB-Instanz SSL aktiviert",
		"es": "SSL de Instancia MongoDB Habilitado",
		"fr": "SSL d'Instance MongoDB Activé",
		"pt": "SSL de Instância MongoDB Habilitado"
	},
	"description": {
		"en": "MongoDB instances should have SSL enabled to encrypt data in transit.",
		"zh": "MongoDB 实例应开启 SSL 加密以保护传输中的数据。",
		"ja": "MongoDB インスタンスで SSL 暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen SSL-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que las instancias MongoDB tengan cifrado SSL habilitado.",
		"fr": "Garantit que les instances MongoDB ont le chiffrement SSL activé.",
		"pt": "Garante que as instâncias MongoDB tenham criptografia SSL habilitada."
	},
	"reason": {
		"en": "The MongoDB instance does not have SSL enabled.",
		"zh": "MongoDB 实例未开启 SSL 加密。",
		"ja": "SSL はクライアントとデータベース間で転送されるデータを保護します。",
		"de": "SSL schützt Daten während der Übertragung zwischen Client und Datenbank.",
		"es": "SSL protege los datos en tránsito entre el cliente y la base de datos.",
		"fr": "SSL protège les données en transit entre le client et la base de données.",
		"pt": "SSL protege dados em trânsito entre o cliente e o banco de dados."
	},
	"recommendation": {
		"en": "Set ssl_action to 'Open' to enable SSL encryption.",
		"zh": "将 ssl_action 设置为 'Open' 以启用 SSL 加密。",
		"ja": "MongoDB インスタンスの SSL を有効にします。",
		"de": "Aktivieren Sie SSL für die MongoDB-Instanz.",
		"es": "Habilite SSL para la instancia MongoDB.",
		"fr": "Activez SSL pour l'instance MongoDB.",
		"pt": "Habilite SSL para a instância MongoDB."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	tf.get_attribute(resource, "ssl_action", "Close") != "Open"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
