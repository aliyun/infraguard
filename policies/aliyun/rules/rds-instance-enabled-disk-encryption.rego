package infraguard.rules.aliyun.rds_instance_enabled_disk_encryption

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rds-instance-enabled-disk-encryption",
	"name": {
		"en": "RDS Instance Disk Encryption Enabled",
		"zh": "RDS 实例开启磁盘加密",
		"ja": "RDS インスタンスのディスク暗号化が有効",
		"de": "RDS-Instanz-Disk-Verschlüsselung aktiviert",
		"es": "Cifrado de Disco de Instancia RDS Habilitado",
		"fr": "Chiffrement de Disque d'Instance RDS Activé",
		"pt": "Criptografia de Disco de Instância RDS Habilitada",
	},
	"severity": "high",
	"description": {
		"en": "Ensures RDS instances have disk encryption enabled.",
		"zh": "确保 RDS 实例开启了磁盘加密。",
		"ja": "RDS インスタンスでディスク暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass RDS-Instanzen Disk-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que las instancias RDS tengan cifrado de disco habilitado.",
		"fr": "Garantit que les instances RDS ont le chiffrement de disque activé.",
		"pt": "Garante que as instâncias RDS tenham criptografia de disco habilitada.",
	},
	"reason": {
		"en": "Disk encryption protects the underlying data storage from unauthorized physical access.",
		"zh": "磁盘加密保护底层数据存储免受未经授权的物理访问。",
		"ja": "ディスク暗号化により、基盤となるデータストレージが不正な物理アクセスから保護されます。",
		"de": "Disk-Verschlüsselung schützt den zugrundeliegenden Datenspeicher vor unbefugtem physischem Zugriff.",
		"es": "El cifrado de disco protege el almacenamiento de datos subyacente del acceso físico no autorizado.",
		"fr": "Le chiffrement de disque protège le stockage de données sous-jacent contre l'accès physique non autorisé.",
		"pt": "A criptografia de disco protege o armazenamento de dados subjacente contra acesso físico não autorizado.",
	},
	"recommendation": {
		"en": "Enable disk encryption for the RDS instance.",
		"zh": "为 RDS 实例开启磁盘加密。",
		"ja": "RDS インスタンスでディスク暗号化を有効にします。",
		"de": "Aktivieren Sie Disk-Verschlüsselung für die RDS-Instanz.",
		"es": "Habilite el cifrado de disco para la instancia RDS.",
		"fr": "Activez le chiffrement de disque pour l'instance RDS.",
		"pt": "Habilite criptografia de disco para a instância RDS.",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	# EncryptionKey being set usually indicates disk encryption is enabled.
	helpers.has_property(resource, "EncryptionKey")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EncryptionKey"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
