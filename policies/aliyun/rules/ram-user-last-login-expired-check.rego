package infraguard.rules.aliyun.ram_user_last_login_expired_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-user-last-login-expired-check",
	"name": {
		"en": "RAM User Last Login Check",
		"zh": "RAM 用户最后登录时间核查",
		"ja": "RAM ユーザー最終ログインチェック",
		"de": "RAM-Benutzer letzte Anmeldung-Prüfung",
		"es": "Verificación de Último Inicio de Sesión de Usuario RAM",
		"fr": "Vérification de la Dernière Connexion d'Utilisateur RAM",
		"pt": "Verificação de Último Login de Usuário RAM",
	},
	"severity": "low",
	"description": {
		"en": "Checks if RAM users have not logged in for a long time.",
		"zh": "核查 RAM 用户是否长时间未登录。",
		"ja": "RAM ユーザーが長時間ログインしていないかどうかをチェックします。",
		"de": "Prüft, ob RAM-Benutzer seit langer Zeit nicht angemeldet waren.",
		"es": "Verifica si los usuarios RAM no han iniciado sesión durante mucho tiempo.",
		"fr": "Vérifie si les utilisateurs RAM ne se sont pas connectés depuis longtemps.",
		"pt": "Verifica se usuários RAM não fizeram login há muito tempo.",
	},
	"reason": {
		"en": "Inactive users should be removed to reduce security surface.",
		"zh": "不活跃的用户应予以移除以减少安全暴露面。",
		"ja": "非アクティブなユーザーは、セキュリティ面を減らすために削除する必要があります。",
		"de": "Inaktive Benutzer sollten entfernt werden, um die Sicherheitsfläche zu reduzieren.",
		"es": "Los usuarios inactivos deben eliminarse para reducir la superficie de seguridad.",
		"fr": "Les utilisateurs inactifs doivent être supprimés pour réduire la surface de sécurité.",
		"pt": "Usuários inativos devem ser removidos para reduzir a superfície de segurança.",
	},
	"recommendation": {
		"en": "Remove or deactivate unused RAM users.",
		"zh": "移除或禁用不常用的 RAM 用户。",
		"ja": "未使用の RAM ユーザーを削除または無効化します。",
		"de": "Entfernen oder deaktivieren Sie nicht verwendete RAM-Benutzer.",
		"es": "Elimine o desactive usuarios RAM no utilizados.",
		"fr": "Supprimez ou désactivez les utilisateurs RAM non utilisés.",
		"pt": "Remova ou desative usuários RAM não utilizados.",
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

# Always compliant in static analysis as runtime data is missing
is_compliant(resource) := true

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": [],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
