package infraguard.rules.terraform.nas_filesystem_encrypt_type_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "nas-filesystem-encrypt-type-check",
	"severity": "low",
	"name": {
		"en": "NAS file system encryption configured",
		"zh": "NAS 文件系统设置了加密",
		"ja": "NAS ファイルシステムの暗号化設定",
		"de": "NAS-Dateisystem-Verschlüsselung konfiguriert",
		"es": "Cifrado del sistema de archivos NAS configurado",
		"fr": "Chiffrement du système de fichiers NAS configuré",
		"pt": "Criptografia do sistema de arquivos NAS configurada"
	},
	"description": {
		"en": "Ensures that NAS file systems have encryption enabled (encrypt_type set to 1 or 2).",
		"zh": "确保 NAS 文件系统已启用加密（encrypt_type 设置为 1 或 2）。",
		"ja": "NAS ファイルシステムで暗号化が有効になっていることを確認します（encrypt_type が 1 または 2 に設定）。",
		"de": "Stellt sicher, dass NAS-Dateisysteme die Verschlüsselung aktiviert haben (encrypt_type auf 1 oder 2 gesetzt).",
		"es": "Garantiza que los sistemas de archivos NAS tengan el cifrado habilitado (encrypt_type establecido en 1 o 2).",
		"fr": "Garantit que les systèmes de fichiers NAS ont le chiffrement activé (encrypt_type défini sur 1 ou 2).",
		"pt": "Garante que os sistemas de arquivos NAS tenham a criptografia habilitada (encrypt_type definido como 1 ou 2)."
	},
	"reason": {
		"en": "The NAS file system does not have encryption configured, which may expose data at rest to unauthorized access.",
		"zh": "NAS 文件系统未配置加密，可能导致静态数据面临未授权访问风险。",
		"ja": "NAS ファイルシステムに暗号化が設定されていないため、保存データが不正アクセスにさらされる可能性があります。",
		"de": "Das NAS-Dateisystem hat keine Verschlüsselung konfiguriert, was ruhende Daten unbefugtem Zugriff aussetzen kann.",
		"es": "El sistema de archivos NAS no tiene cifrado configurado, lo que puede exponer los datos en reposo a acceso no autorizado.",
		"fr": "Le système de fichiers NAS n'a pas de chiffrement configuré, ce qui peut exposer les données au repos à un accès non autorisé.",
		"pt": "O sistema de arquivos NAS não tem criptografia configurada, o que pode expor dados em repouso a acesso não autorizado."
	},
	"recommendation": {
		"en": "Set encrypt_type to \"1\" (NAS-managed encryption) or \"2\" (KMS encryption) to enable encryption for the NAS file system.",
		"zh": "将 encrypt_type 设置为 \"1\"（NAS 托管加密）或 \"2\"（KMS 加密）以启用 NAS 文件系统加密。",
		"ja": "encrypt_type を \"1\"（NAS 管理暗号化）または \"2\"（KMS 暗号化）に設定して、NAS ファイルシステムの暗号化を有効にします。",
		"de": "Setzen Sie encrypt_type auf \"1\" (NAS-verwaltete Verschlüsselung) oder \"2\" (KMS-Verschlüsselung), um die Verschlüsselung für das NAS-Dateisystem zu aktivieren.",
		"es": "Establezca encrypt_type en \"1\" (cifrado gestionado por NAS) o \"2\" (cifrado KMS) para habilitar el cifrado del sistema de archivos NAS.",
		"fr": "Définissez encrypt_type sur \"1\" (chiffrement géré par NAS) ou \"2\" (chiffrement KMS) pour activer le chiffrement du système de fichiers NAS.",
		"pt": "Defina encrypt_type como \"1\" (criptografia gerenciada pelo NAS) ou \"2\" (criptografia KMS) para habilitar a criptografia do sistema de arquivos NAS."
	},
	"resource_types": ["alicloud_nas_file_system"],
	"iac_type": "terraform"
}

is_encrypted(value) if value == 1

is_encrypted(value) if value == "1"

is_encrypted(value) if value == 2

is_encrypted(value) if value == "2"

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_nas_file_system")
	encrypt_type := tf.get_attribute(resource, "encrypt_type", "0")
	not is_encrypted(encrypt_type)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_nas_file_system.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
