package infraguard.rules.terraform.rds_instance_enabled_tde_disk_encryption

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-instance-enabled-tde-disk-encryption",
	"severity": "medium",
	"name": {
		"en": "RDS Instance Enabled TDE or Disk Encryption",
		"zh": "RDS 实例开启 TDE 或者数据盘加密",
		"ja": "RDS インスタンス TDE またはディスク暗号化が有効",
		"de": "RDS-Instanz TDE oder Festplattenverschlüsselung aktiviert",
		"es": "Instancia RDS TDE o Cifrado de Disco Habilitado",
		"fr": "Instance RDS TDE ou Chiffrement de Disque Activé",
		"pt": "Instância RDS TDE ou Criptografia de Disco Habilitada"
	},
	"description": {
		"en": "RDS instance should have TDE (Transparent Data Encryption) or disk encryption enabled.",
		"zh": "RDS 实例开启 TDE 或者数据盘加密，视为合规。",
		"ja": "RDS インスタンスで TDE（透過的データ暗号化）またはディスク暗号化を有効にする必要があります。",
		"de": "RDS-Instanz sollte TDE (Transparent Data Encryption) oder Festplattenverschlüsselung aktiviert haben.",
		"es": "La instancia RDS debe tener TDE (Cifrado Transparente de Datos) o cifrado de disco habilitado.",
		"fr": "L'instance RDS doit avoir TDE (Chiffrement Transparent des Données) ou le chiffrement de disque activé.",
		"pt": "A instância RDS deve ter TDE (Criptografia Transparente de Dados) ou criptografia de disco habilitada."
	},
	"reason": {
		"en": "RDS instance does not have TDE or disk encryption enabled, which may expose data to security risks.",
		"zh": "RDS 实例未开启 TDE 或数据盘加密，可能导致数据面临安全风险。",
		"ja": "RDS インスタンスで TDE またはディスク暗号化が有効になっていないため、データがセキュリティリスクにさらされる可能性があります。",
		"de": "RDS-Instanz hat keine TDE oder Festplattenverschlüsselung aktiviert, was Daten Sicherheitsrisiken aussetzen kann.",
		"es": "La instancia RDS no tiene TDE o cifrado de disco habilitado, lo que puede exponer los datos a riesgos de seguridad.",
		"fr": "L'instance RDS n'a pas TDE ou le chiffrement de disque activé, ce qui peut exposer les données à des risques de sécurité.",
		"pt": "A instância RDS não tem TDE ou criptografia de disco habilitada, o que pode expor os dados a riscos de segurança."
	},
	"recommendation": {
		"en": "Set tde_status to \"Enabled\" or configure encryption_key for the RDS instance.",
		"zh": "为 RDS 实例将 tde_status 设置为 \"Enabled\" 或配置 encryption_key。",
		"ja": "RDS インスタンスの tde_status を \"Enabled\" に設定するか、encryption_key を設定します。",
		"de": "Setzen Sie tde_status auf \"Enabled\" oder konfigurieren Sie encryption_key für die RDS-Instanz.",
		"es": "Establezca tde_status en \"Enabled\" o configure encryption_key para la instancia RDS.",
		"fr": "Définissez tde_status sur \"Enabled\" ou configurez encryption_key pour l'instance RDS.",
		"pt": "Defina tde_status como \"Enabled\" ou configure encryption_key para a instância RDS."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

is_tde_enabled(resource) if {
	tf.get_attribute(resource, "tde_status", "") == "Enabled"
}

is_tde_enabled(resource) if {
	key := tf.get_attribute(resource, "encryption_key", "")
	key != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	not is_tde_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
