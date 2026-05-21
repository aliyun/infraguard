package infraguard.rules.aliyun.ram_user_no_policy_check

import data.infraguard.helpers
import rego.v1

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
		"en": "Attach a policy to the user or remove the user.",
		"zh": "为该用户挂载策略，或将其移除。",
		"ja": "ユーザーにポリシーをアタッチするか、ユーザーを削除します。",
		"de": "Hängen Sie eine Richtlinie an den Benutzer an oder entfernen Sie den Benutzer.",
		"es": "Adjunte una política al usuario o elimine el usuario.",
		"fr": "Attachez une politique à l'utilisateur ou supprimez l'utilisateur.",
		"pt": "Anexe uma política ao usuário ou remova o usuário."
	},
	"resource_types": ["ALIYUN::RAM::User"]
}

has_policy(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_referencing(user_name_val, user_name)
}

has_policy(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_get_att_referencing(user_name_val, user_name)
}

has_policy(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	name == user_name
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	custom_policies := object.get(policy_attachments, "Custom", [])
	count(system_policies) > 0
}

has_policy(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	name == user_name
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	custom_policies := object.get(policy_attachments, "Custom", [])
	count(custom_policies) > 0
}

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	not has_policy(user_name)
	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
