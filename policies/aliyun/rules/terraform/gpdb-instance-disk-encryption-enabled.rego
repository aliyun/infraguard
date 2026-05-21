package infraguard.rules.terraform.gpdb_instance_disk_encryption_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "gpdb-instance-disk-encryption-enabled",
	"severity": "high",
	"name": {
		"en": "GPDB Instance Disk Encryption Enabled",
		"zh": "GPDB 实例开启磁盘加密",
		"ja": "GPDB ディスク暗号化が有効",
		"de": "GPDB-Disk-Verschlüsselung aktiviert",
		"es": "Cifrado de Disco GPDB Habilitado",
		"fr": "Chiffrement de Disque GPDB Activé",
		"pt": "Criptografia de Disco GPDB Habilitada"
	},
	"description": {
		"en": "GPDB instances should have disk encryption enabled using KMS encryption key.",
		"zh": "GPDB 实例应使用 KMS 加密密钥开启磁盘加密，视为合规。",
		"ja": "GPDB インスタンスでディスク暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass GPDB-Instanzen Disk-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que las instancias GPDB tengan cifrado de disco habilitado.",
		"fr": "Garantit que les instances GPDB ont le chiffrement de disque activé.",
		"pt": "Garante que as instâncias GPDB tenham criptografia de disco habilitada."
	},
	"reason": {
		"en": "The GPDB instance does not have disk encryption enabled.",
		"zh": "GPDB 实例未开启磁盘加密。",
		"ja": "保存時の暗号化により、機密データベースファイルが不正アクセスから保護されます。",
		"de": "Verschlüsselung im Ruhezustand schützt sensible Datenbankdateien vor unbefugtem Zugriff.",
		"es": "El cifrado en reposo protege los archivos de base de datos sensibles del acceso no autorizado.",
		"fr": "Le chiffrement au repos protège les fichiers de base de données sensibles contre l'accès non autorisé.",
		"pt": "A criptografia em repouso protege arquivos de banco de dados sensíveis contra acesso não autorizado."
	},
	"recommendation": {
		"en": "Enable disk encryption by specifying the encryption_key attribute with a valid KMS key ID.",
		"zh": "通过指定 encryption_key 属性并设置有效的 KMS 密钥 ID 来开启磁盘加密。",
		"ja": "GPDB インスタンスに KMS を使用してディスク暗号化を有効にします。",
		"de": "Aktivieren Sie Disk-Verschlüsselung mit KMS für die GPDB-Instanz.",
		"es": "Habilite el cifrado de disco usando KMS para la instancia GPDB.",
		"fr": "Activez le chiffrement de disque en utilisant KMS pour l'instance GPDB.",
		"pt": "Habilite a criptografia de disco usando KMS para a instância GPDB."
	},
	"resource_types": ["alicloud_gpdb_instance"],
	"iac_type": "terraform"
}

# Check if disk encryption is enabled
is_encryption_enabled(resource) if {
	key := tf.get_attribute(resource, "encryption_key", "")
	not tf.is_unknown(key)
	key != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_gpdb_instance")
	not is_encryption_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_gpdb_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
