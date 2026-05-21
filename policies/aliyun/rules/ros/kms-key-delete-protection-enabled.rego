package infraguard.rules.aliyun.kms_key_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "kms-key-delete-protection-enabled",
	"severity": "medium",
	"name": {
		"en": "KMS key deletion protection enabled",
		"zh": "KMS 主密钥开启删除保护",
		"ja": "KMS キー削除保護が有効",
		"de": "KMS-Schlüssel-Löschschutz aktiviert",
		"es": "Protección de Eliminación de Clave KMS Habilitada",
		"fr": "Protection contre la Suppression de Clé KMS Activée",
		"pt": "Proteção de Exclusão de Chave KMS Habilitada"
	},
	"description": {
		"en": "KMS master key has deletion protection enabled, considered compliant. Keys not in enabled status and service keys (which cannot be deleted) are not applicable.",
		"zh": "KMS 主密钥开启删除保护,视为合规。如果密钥状态非启用中,视为不适用,如果密钥为服务密钥,由于本身不可删除,视为不适用。",
		"ja": "KMS マスターキーで削除保護が有効になっている場合、準拠と見なされます。有効状態でないキーとサービスキー（削除できない）は適用されません。",
		"de": "KMS-Masterschlüssel hat Löschschutz aktiviert, gilt als konform. Schlüssel, die nicht im aktivierten Status sind, und Dienstschlüssel (die nicht gelöscht werden können) sind nicht anwendbar.",
		"es": "La clave maestra KMS tiene protección de eliminación habilitada, se considera conforme. Las claves que no están en estado habilitado y las claves de servicio (que no se pueden eliminar) no son aplicables.",
		"fr": "La clé maître KMS a la protection contre la suppression activée, considérée comme conforme. Les clés qui ne sont pas en état activé et les clés de service (qui ne peuvent pas être supprimées) ne sont pas applicables.",
		"pt": "A chave mestra KMS tem proteção de exclusão habilitada, considerada em conformidade. Chaves que não estão em status habilitado e chaves de serviço (que não podem ser excluídas) não são aplicáveis."
	},
	"reason": {
		"en": "KMS key does not have deletion protection enabled",
		"zh": "KMS 主密钥未开启删除保护",
		"ja": "KMS キーで削除保護が有効になっていません",
		"de": "KMS-Schlüssel hat keinen Löschschutz aktiviert",
		"es": "La clave KMS no tiene protección de eliminación habilitada",
		"fr": "La clé KMS n'a pas la protection contre la suppression activée",
		"pt": "A chave KMS não tem proteção de exclusão habilitada"
	},
	"recommendation": {
		"en": "Enable deletion protection for KMS key to prevent accidental deletion of critical encryption keys",
		"zh": "为 KMS 主密钥启用删除保护以防止意外删除关键加密密钥",
		"ja": "重要な暗号化キーの誤削除を防ぐために、KMS キーの削除保護を有効にします",
		"de": "Aktivieren Sie den Löschschutz für den KMS-Schlüssel, um versehentliches Löschen kritischer Verschlüsselungsschlüssel zu verhindern",
		"es": "Habilite la protección de eliminación para la clave KMS para prevenir la eliminación accidental de claves de cifrado críticas",
		"fr": "Activez la protection contre la suppression pour la clé KMS pour empêcher la suppression accidentelle de clés de chiffrement critiques",
		"pt": "Habilite a proteção de exclusão para a chave KMS para prevenir a exclusão acidental de chaves de criptografia críticas"
	},
	"resource_types": ["ALIYUN::KMS::Key"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KMS::Key")

	# Check if DeletionProtection is enabled
	deletion_protection := helpers.get_property(resource, "DeletionProtection", false)
	not helpers.is_true(deletion_protection)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
