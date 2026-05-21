package infraguard.rules.aliyun.root_ak_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "root-ak-check",
	"severity": "high",
	"name": {
		"en": "Root User AccessKey Check",
		"zh": "主账号 AccessKey 检测",
		"ja": "ルートユーザー AccessKey チェック",
		"de": "Root-Benutzer AccessKey-Prüfung",
		"es": "Verificación de AccessKey de Usuario Root",
		"fr": "Vérification de la Clé d'Accès Utilisateur Root",
		"pt": "Verificação de AccessKey do Usuário Root"
	},
	"description": {
		"en": "Ensures that the root account does not have active AccessKeys.",
		"zh": "确保主账号没有激活的 AccessKey。",
		"ja": "ルートアカウントにアクティブな AccessKey がないことを確認します。",
		"de": "Stellt sicher, dass das Root-Konto keine aktiven AccessKeys hat.",
		"es": "Garantiza que la cuenta root no tenga AccessKeys activos.",
		"fr": "Garantit que le compte root n'a pas de clés d'accès actives.",
		"pt": "Garante que a conta root não possui AccessKeys ativos."
	},
	"reason": {
		"en": "Using AccessKeys for the root account is a security risk. IAM roles or RAM user AccessKeys should be used instead.",
		"zh": "为主账号使用 AccessKey 存在安全风险。应改为使用 RAM 角色或 RAM 用户 AccessKey。",
		"ja": "ルートアカウントに AccessKey を使用することはセキュリティリスクです。代わりに IAM ロールまたは RAM ユーザー AccessKey を使用する必要があります。",
		"de": "Die Verwendung von AccessKeys für das Root-Konto ist ein Sicherheitsrisiko. Stattdessen sollten IAM-Rollen oder RAM-Benutzer-AccessKeys verwendet werden.",
		"es": "Usar AccessKeys para la cuenta root es un riesgo de seguridad. En su lugar, se deben usar roles IAM o AccessKeys de usuario RAM.",
		"fr": "Utiliser des clés d'accès pour le compte root est un risque de sécurité. Des rôles IAM ou des clés d'accès utilisateur RAM doivent être utilisés à la place.",
		"pt": "Usar AccessKeys para a conta root é um risco de segurança. Em vez disso, devem ser usadas funções IAM ou AccessKeys de usuário RAM."
	},
	"recommendation": {
		"en": "Delete any AccessKeys associated with the root account and use RAM users or roles.",
		"zh": "删除主账号的所有 AccessKey，并使用 RAM 用户或角色。",
		"ja": "ルートアカウントに関連付けられているすべての AccessKey を削除し、RAM ユーザーまたはロールを使用します。",
		"de": "Löschen Sie alle mit dem Root-Konto verknüpften AccessKeys und verwenden Sie RAM-Benutzer oder Rollen.",
		"es": "Elimine cualquier AccessKey asociado con la cuenta root y use usuarios o roles RAM.",
		"fr": "Supprimez toutes les clés d'accès associées au compte root et utilisez des utilisateurs ou des rôles RAM.",
		"pt": "Exclua quaisquer AccessKeys associados à conta root e use usuários ou funções RAM."
	},
	"resource_types": ["ALIYUN::RAM::User"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	name == "root"
	helpers.has_property(resource, "AccessKey") # Conceptual check
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AccessKey"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
