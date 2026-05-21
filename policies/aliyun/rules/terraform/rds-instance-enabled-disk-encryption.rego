package infraguard.rules.terraform.rds_instance_enabled_disk_encryption

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-instance-enabled-disk-encryption",
	"severity": "medium",
	"name": {
		"en": "RDS Instance Disk Encryption Enabled",
		"zh": "RDS 实例开启磁盘加密",
		"ja": "RDS インスタンスのディスク暗号化が有効",
		"de": "RDS-Instanz-Disk-Verschlüsselung aktiviert",
		"es": "Cifrado de Disco de Instancia RDS Habilitado",
		"fr": "Chiffrement de Disque d'Instance RDS Activé",
		"pt": "Criptografia de Disco de Instância RDS Habilitada"
	},
	"description": {
		"en": "Ensures RDS instances have disk encryption enabled.",
		"zh": "确保 RDS 实例开启了磁盘加密。",
		"ja": "RDS インスタンスでディスク暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass RDS-Instanzen Disk-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que las instancias RDS tengan cifrado de disco habilitado.",
		"fr": "Garantit que les instances RDS ont le chiffrement de disque activé.",
		"pt": "Garante que as instâncias RDS tenham criptografia de disco habilitada."
	},
	"reason": {
		"en": "Disk encryption protects the underlying data storage from unauthorized physical access.",
		"zh": "磁盘加密保护底层数据存储免受未经授权的物理访问。",
		"ja": "ディスク暗号化により、基盤となるデータストレージが不正な物理アクセスから保護されます。",
		"de": "Disk-Verschlüsselung schützt den zugrundeliegenden Datenspeicher vor unbefugtem physischem Zugriff.",
		"es": "El cifrado de disco protege el almacenamiento de datos subyacente del acceso físico no autorizado.",
		"fr": "Le chiffrement de disque protège le stockage de données sous-jacent contre l'accès physique non autorisé.",
		"pt": "A criptografia de disco protege o armazenamento de dados subjacente contra acesso físico não autorizado."
	},
	"recommendation": {
		"en": "Set encryption_key for the RDS instance to enable disk encryption.",
		"zh": "为 RDS 实例设置 encryption_key 以开启磁盘加密。",
		"ja": "RDS インスタンスの encryption_key を設定してディスク暗号化を有効にします。",
		"de": "Setzen Sie encryption_key für die RDS-Instanz, um Disk-Verschlüsselung zu aktivieren.",
		"es": "Establezca encryption_key para la instancia RDS para habilitar el cifrado de disco.",
		"fr": "Définissez encryption_key pour l'instance RDS pour activer le chiffrement de disque.",
		"pt": "Defina encryption_key para a instância RDS para habilitar criptografia de disco."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	key := tf.get_attribute(resource, "encryption_key", "")
	key == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
