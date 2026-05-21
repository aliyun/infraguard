package infraguard.rules.terraform.ram_policy_in_use_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-policy-in-use-check",
	"severity": "low",
	"name": {
		"en": "RAM Policy In Use Check",
		"zh": "RAM 权限策略使用检测",
		"ja": "RAM ポリシー使用チェック",
		"de": "RAM-Richtlinie In Verwendung Prüfung",
		"es": "Verificación de Política RAM en Uso",
		"fr": "Vérification de Politique RAM en Utilisation",
		"pt": "Verificação de Política RAM em Uso"
	},
	"description": {
		"en": "Ensures RAM policies are attached to at least one RAM user, group, or role.",
		"zh": "确保 RAM 权限策略至少绑定到一个 RAM 用户、用户组或角色。",
		"ja": "RAM ポリシーが少なくとも 1 つの RAM ユーザー、グループ、またはロールにアタッチされていることを確認します。",
		"de": "Stellt sicher, dass RAM-Richtlinien an mindestens einen RAM-Benutzer, eine Gruppe oder eine Rolle angehängt sind.",
		"es": "Garantiza que las políticas RAM estén adjuntas a al menos un usuario, grupo o rol RAM.",
		"fr": "Garantit que les politiques RAM sont attachées à au moins un utilisateur, groupe ou rôle RAM.",
		"pt": "Garante que as políticas RAM estejam anexadas a pelo menos um usuário, grupo ou função RAM."
	},
	"reason": {
		"en": "Idle policies increase management complexity and should be removed.",
		"zh": "闲置的权限策略会增加管理复杂性，应予以移除。",
		"ja": "アイドルポリシーは管理の複雑さを増し、削除する必要があります。",
		"de": "Inaktive Richtlinien erhöhen die Verwaltungskomplexität und sollten entfernt werden.",
		"es": "Las políticas inactivas aumentan la complejidad de gestión y deben eliminarse.",
		"fr": "Les politiques inactives augmentent la complexité de gestion et doivent être supprimées.",
		"pt": "Políticas ociosas aumentam a complexidade de gerenciamento e devem ser removidas."
	},
	"recommendation": {
		"en": "Add an alicloud_ram_role_policy_attachment, alicloud_ram_user_policy_attachment, or alicloud_ram_group_policy_attachment resource, or remove the unused policy.",
		"zh": "添加 alicloud_ram_role_policy_attachment、alicloud_ram_user_policy_attachment 或 alicloud_ram_group_policy_attachment 资源，或移除未使用的策略。",
		"ja": "alicloud_ram_role_policy_attachment、alicloud_ram_user_policy_attachment、または alicloud_ram_group_policy_attachment リソースを追加するか、未使用のポリシーを削除します。",
		"de": "Fügen Sie eine alicloud_ram_role_policy_attachment-, alicloud_ram_user_policy_attachment- oder alicloud_ram_group_policy_attachment-Ressource hinzu oder entfernen Sie die ungenutzte Richtlinie.",
		"es": "Agregue un recurso alicloud_ram_role_policy_attachment, alicloud_ram_user_policy_attachment o alicloud_ram_group_policy_attachment, o elimine la política no utilizada.",
		"fr": "Ajoutez une ressource alicloud_ram_role_policy_attachment, alicloud_ram_user_policy_attachment ou alicloud_ram_group_policy_attachment, ou supprimez la politique non utilisée.",
		"pt": "Adicione um recurso alicloud_ram_role_policy_attachment, alicloud_ram_user_policy_attachment ou alicloud_ram_group_policy_attachment, ou remova a política não utilizada."
	},
	"resource_types": ["alicloud_ram_policy"],
	"iac_type": "terraform"
}

has_attachment if {
	tf.has_resource_type("alicloud_ram_role_policy_attachment")
}

has_attachment if {
	tf.has_resource_type("alicloud_ram_user_policy_attachment")
}

has_attachment if {
	tf.has_resource_type("alicloud_ram_group_policy_attachment")
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_policy")
	not has_attachment
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_policy.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
