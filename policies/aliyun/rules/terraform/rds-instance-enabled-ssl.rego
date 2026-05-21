package infraguard.rules.terraform.rds_instance_enabled_ssl

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-instance-enabled-ssl",
	"severity": "medium",
	"name": {
		"en": "RDS Instance SSL Enabled",
		"zh": "RDS 实例开启 SSL 加密",
		"ja": "RDS インスタンスで SSL が有効",
		"de": "RDS-Instanz SSL aktiviert",
		"es": "SSL de Instancia RDS Habilitado",
		"fr": "SSL d'Instance RDS Activé",
		"pt": "SSL de Instância RDS Habilitado"
	},
	"description": {
		"en": "Ensures RDS instances have SSL encryption enabled.",
		"zh": "确保 RDS 实例开启了 SSL 加密。",
		"ja": "RDS インスタンスで SSL 暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass RDS-Instanzen SSL-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que las instancias RDS tengan cifrado SSL habilitado.",
		"fr": "Garantit que les instances RDS ont le chiffrement SSL activé.",
		"pt": "Garante que as instâncias RDS tenham criptografia SSL habilitada."
	},
	"reason": {
		"en": "SSL encryption protects data in transit from eavesdropping and tampering.",
		"zh": "SSL 加密可保护传输中的数据免受窃听和篡改。",
		"ja": "SSL 暗号化により、送信中のデータが盗聴や改ざんから保護されます。",
		"de": "SSL-Verschlüsselung schützt Daten während der Übertragung vor Abhören und Manipulation.",
		"es": "El cifrado SSL protege los datos en tránsito contra interceptación y manipulación.",
		"fr": "Le chiffrement SSL protège les données en transit contre l'écoute et la falsification.",
		"pt": "A criptografia SSL protege dados em trânsito contra interceptação e adulteração."
	},
	"recommendation": {
		"en": "Set ssl_action to \"Open\" for the RDS instance to enable SSL.",
		"zh": "为 RDS 实例将 ssl_action 设置为 \"Open\" 以开启 SSL。",
		"ja": "RDS インスタンスの ssl_action を \"Open\" に設定して SSL を有効にします。",
		"de": "Setzen Sie ssl_action für die RDS-Instanz auf \"Open\", um SSL zu aktivieren.",
		"es": "Establezca ssl_action en \"Open\" para la instancia RDS para habilitar SSL.",
		"fr": "Définissez ssl_action sur \"Open\" pour l'instance RDS pour activer SSL.",
		"pt": "Defina ssl_action como \"Open\" para a instância RDS para habilitar SSL."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

is_ssl_enabled(resource) if {
	tf.get_attribute(resource, "ssl_action", "") == "Open"
}

is_ssl_enabled(resource) if {
	status := tf.get_attribute(resource, "ssl_status", "Disabled")
	status != "Disabled"
	status != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	not is_ssl_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
