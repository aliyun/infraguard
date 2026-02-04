package infraguard.rules.aliyun.gpdb_instance_disk_encryption_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "gpdb-instance-disk-encryption-enabled",
	"name": {
		"en": "GPDB Disk Encryption Enabled",
		"zh": "GPDB 开启磁盘加密",
		"ja": "GPDB ディスク暗号化が有効",
		"de": "GPDB-Disk-Verschlüsselung aktiviert",
		"es": "Cifrado de Disco GPDB Habilitado",
		"fr": "Chiffrement de Disque GPDB Activé",
		"pt": "Criptografia de Disco GPDB Habilitada"
	},
	"severity": "high",
	"description": {
		"en": "Ensures GPDB instances have disk encryption enabled.",
		"zh": "确保 GPDB 实例开启了磁盘加密。",
		"ja": "GPDB インスタンスでディスク暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass GPDB-Instanzen Disk-Verschlüsselung aktiviert haben.",
		"es": "Garantiza que las instancias GPDB tengan cifrado de disco habilitado.",
		"fr": "Garantit que les instances GPDB ont le chiffrement de disque activé.",
		"pt": "Garante que as instâncias GPDB tenham criptografia de disco habilitada."
	},
	"reason": {
		"en": "Encryption at rest protects sensitive database files from unauthorized access.",
		"zh": "静态加密保护敏感数据库文件免受未经授权的访问。",
		"ja": "保存時の暗号化により、機密データベースファイルが不正アクセスから保護されます。",
		"de": "Verschlüsselung im Ruhezustand schützt sensible Datenbankdateien vor unbefugtem Zugriff.",
		"es": "El cifrado en reposo protege los archivos de base de datos sensibles del acceso no autorizado.",
		"fr": "Le chiffrement au repos protège les fichiers de base de données sensibles contre l'accès non autorisé.",
		"pt": "A criptografia em repouso protege arquivos de banco de dados sensíveis contra acesso não autorizado."
	},
	"recommendation": {
		"en": "Enable disk encryption using KMS for the GPDB instance.",
		"zh": "使用 KMS 为 GPDB 实例开启磁盘加密。",
		"ja": "GPDB インスタンスに KMS を使用してディスク暗号化を有効にします。",
		"de": "Aktivieren Sie Disk-Verschlüsselung mit KMS für die GPDB-Instanz.",
		"es": "Habilite el cifrado de disco usando KMS para la instancia GPDB.",
		"fr": "Activez le chiffrement de disque en utilisant KMS pour l'instance GPDB.",
		"pt": "Habilite a criptografia de disco usando KMS para a instância GPDB."
	},
	"resource_types": ["ALIYUN::GPDB::DBInstance"],
}

is_compliant(resource) if {
	# EncryptionKey being set usually indicates encryption is enabled.
	helpers.has_property(resource, "EncryptionKey")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::GPDB::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EncryptionKey"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
