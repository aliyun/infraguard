package infraguard.rules.aliyun.root_mfa_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "root-mfa-check",
	"name": {
		"en": "Root User MFA Check",
		"zh": "主账号 MFA 检测",
		"de": "Root-Benutzer MFA-Prüfung",
		"ja": "ルートユーザー MFA チェック",
		"es": "Verificación de MFA de Usuario Root",
		"fr": "Vérification MFA Utilisateur Root",
		"pt": "Verificação de MFA do Usuário Root",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Multi-Factor Authentication (MFA) is enabled for the root account.",
		"zh": "确保主账号已开启多因素认证(MFA)。",
		"de": "Stellt sicher, dass die Multi-Faktor-Authentifizierung (MFA) für das Root-Konto aktiviert ist.",
		"ja": "ルートアカウントで多要素認証（MFA）が有効になっていることを確認します。",
		"es": "Garantiza que la autenticación multifactor (MFA) esté habilitada para la cuenta root.",
		"fr": "Garantit que l'authentification multifacteur (MFA) est activée pour le compte root.",
		"pt": "Garante que a autenticação multifator (MFA) está habilitada para a conta root.",
	},
	"reason": {
		"en": "MFA provides an extra layer of security for the most privileged account in the cloud environment.",
		"zh": "MFA 为云环境中最具特权的账号提供了额外的安全层。",
		"de": "MFA bietet eine zusätzliche Sicherheitsebene für das privilegierteste Konto in der Cloud-Umgebung.",
		"ja": "MFA は、クラウド環境で最も権限の高いアカウントに追加のセキュリティ層を提供します。",
		"es": "MFA proporciona una capa adicional de seguridad para la cuenta con más privilegios en el entorno en la nube.",
		"fr": "MFA fournit une couche supplémentaire de sécurité pour le compte le plus privilégié dans l'environnement cloud.",
		"pt": "O MFA fornece uma camada extra de segurança para a conta mais privilegiada no ambiente em nuvem.",
	},
	"recommendation": {
		"en": "Enable MFA for the Alibaba Cloud root account.",
		"zh": "为阿里云主账号开启 MFA。",
		"de": "Aktivieren Sie MFA für das Alibaba Cloud Root-Konto.",
		"ja": "Alibaba Cloud ルートアカウントで MFA を有効にします。",
		"es": "Habilite MFA para la cuenta root de Alibaba Cloud.",
		"fr": "Activez MFA pour le compte root d'Alibaba Cloud.",
		"pt": "Habilite MFA para a conta root do Alibaba Cloud.",
	},
	"resource_types": ["ALIYUN::RAM::User"], # This is a conceptual check often mapped to User or Account
}

# Conceptual check for root MFA
# In practice, this might be a placeholder or check a specific global configuration if available
deny contains result if {
	# This is a conceptual rule, let's assume we check if any user has MFA enabled
	# or if there's a specific flag. For now, it's a placeholder implementation.
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	name == "root"
	not helpers.get_property(resource, "MFAEnabled", false)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MFAEnabled"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
