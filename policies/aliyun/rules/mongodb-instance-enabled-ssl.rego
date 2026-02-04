package infraguard.rules.aliyun.mongodb_instance_enabled_ssl

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "mongodb-instance-enabled-ssl",
	"name": {
		"en": "MongoDB Instance SSL Enabled",
		"zh": "MongoDB 实例开启 SSL 加密",
		"ja": "MongoDB インスタンス SSL 有効",
		"de": "MongoDB-Instanz SSL aktiviert",
		"es": "SSL de Instancia MongoDB Habilitado",
		"fr": "SSL d'Instance MongoDB Activé",
		"pt": "SSL de Instância MongoDB Habilitado",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures MongoDB instances have SSL encryption enabled.",
		"zh": "确保 MongoDB 实例开启了 SSL 加密。",
		"ja": "MongoDB インスタンスで SSL 暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen SSL-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que las instancias MongoDB tengan cifrado SSL habilitado.",
		"fr": "Garantit que les instances MongoDB ont le chiffrement SSL activé.",
		"pt": "Garante que as instâncias MongoDB tenham criptografia SSL habilitada.",
	},
	"reason": {
		"en": "SSL protects data in transit between the client and the database.",
		"zh": "SSL 保护客户端与数据库之间传输的数据。",
		"ja": "SSL はクライアントとデータベース間で転送されるデータを保護します。",
		"de": "SSL schützt Daten während der Übertragung zwischen Client und Datenbank.",
		"es": "SSL protege los datos en tránsito entre el cliente y la base de datos.",
		"fr": "SSL protège les données en transit entre le client et la base de données.",
		"pt": "SSL protege dados em trânsito entre o cliente e o banco de dados.",
	},
	"recommendation": {
		"en": "Enable SSL for the MongoDB instance.",
		"zh": "为 MongoDB 实例开启 SSL 加密。",
		"ja": "MongoDB インスタンスの SSL を有効にします。",
		"de": "Aktivieren Sie SSL für die MongoDB-Instanz.",
		"es": "Habilite SSL para la instancia MongoDB.",
		"fr": "Activez SSL pour l'instance MongoDB.",
		"pt": "Habilite SSL para a instância MongoDB.",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

is_compliant(resource) if {
	ssl_options := helpers.get_property(resource, "SSLOptions", {})
	action := object.get(ssl_options, "SSLAction", "Close")
	action == "Open"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SSLOptions", "SSLAction"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
