package infraguard.rules.terraform.ram_user_no_policy_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-no-policy-check",
	"severity": "low",
	"name": {
		"en": "RAM User Has Policy",
		"zh": "识别未挂载任何策略的 RAM 用户",
		"ja": "RAM ユーザーにポリシーがある",
		"de": "RAM-Benutzer hat Richtlinie",
		"es": "El Usuario RAM Tiene Política",
		"fr": "L'Utilisateur RAM a une Politique",
		"pt": "O Usuário RAM Tem Política"
	},
	"description": {
		"en": "Ensures RAM users have at least one policy attached.",
		"zh": "确保 RAM 用户至少挂载了一个策略。",
		"ja": "RAM ユーザーに少なくとも 1 つのポリシーがアタッチされていることを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer mindestens eine Richtlinie angehängt haben.",
		"es": "Garantiza que los usuarios RAM tengan al menos una política adjunta.",
		"fr": "Garantit que les utilisateurs RAM ont au moins une politique attachée.",
		"pt": "Garante que os usuários RAM tenham pelo menos uma política anexada."
	},
	"reason": {
		"en": "Users without policies cannot perform any actions and may be redundant.",
		"zh": "没有策略的用户无法执行任何操作，可能是冗余的。",
		"ja": "ポリシーのないユーザーはアクションを実行できず、冗長である可能性があります。",
		"de": "Benutzer ohne Richtlinien können keine Aktionen ausführen und können redundant sein.",
		"es": "Los usuarios sin políticas no pueden realizar ninguna acción y pueden ser redundantes.",
		"fr": "Les utilisateurs sans politiques ne peuvent effectuer aucune action et peuvent être redondants.",
		"pt": "Usuários sem políticas não podem realizar nenhuma ação e podem ser redundantes."
	},
	"recommendation": {
		"en": "Add an alicloud_ram_user_policy_attachment resource or remove the user.",
		"zh": "添加 alicloud_ram_user_policy_attachment 资源，或将该用户移除。",
		"ja": "alicloud_ram_user_policy_attachment リソースを追加するか、ユーザーを削除します。",
		"de": "Fügen Sie eine alicloud_ram_user_policy_attachment-Ressource hinzu oder entfernen Sie den Benutzer.",
		"es": "Agregue un recurso alicloud_ram_user_policy_attachment o elimine el usuario.",
		"fr": "Ajoutez une ressource alicloud_ram_user_policy_attachment ou supprimez l'utilisateur.",
		"pt": "Adicione um recurso alicloud_ram_user_policy_attachment ou remova o usuário."
	},
	"resource_types": ["alicloud_ram_user"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_user")
	not tf.has_resource_type("alicloud_ram_user_policy_attachment")
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_user.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
