package infraguard.rules.aliyun.ram_user_no_has_specified_policy

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-user-no-has-specified-policy",
	"severity": "medium",
	"name": {
		"en": "RAM User No Specified Policy",
		"zh": "RAM 用户及所属用户组未绑定指定条件的权限策略",
		"ja": "RAM ユーザーに指定されたポリシーなし",
		"de": "RAM-Benutzer keine angegebene Richtlinie",
		"es": "Usuario RAM Sin Política Especificada",
		"fr": "Utilisateur RAM Sans Politique Spécifiée",
		"pt": "Usuário RAM Sem Política Especificada"
	},
	"description": {
		"en": "Ensures RAM users do not have specified risky policies attached.",
		"zh": "确保 RAM 用户未绑定符合参数条件的高危权限策略。",
		"ja": "RAM ユーザーに指定されたリスクのあるポリシーが添付されていないことを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer keine angegebenen riskanten Richtlinien angehängt haben.",
		"es": "Garantiza que los usuarios RAM no tengan políticas riesgosas especificadas adjuntas.",
		"fr": "Garantit que les utilisateurs RAM n'ont pas de politiques risquées spécifiées attachées.",
		"pt": "Garante que os usuários RAM não tenham políticas arriscadas especificadas anexadas."
	},
	"reason": {
		"en": "Risky policies increase the attack surface.",
		"zh": "高危策略会增加攻击面。",
		"ja": "リスクのあるポリシーは攻撃面を増加させます。",
		"de": "Riskante Richtlinien erhöhen die Angriffsfläche.",
		"es": "Las políticas riesgosas aumentan la superficie de ataque.",
		"fr": "Les politiques risquées augmentent la surface d'attaque.",
		"pt": "Políticas arriscadas aumentam a superfície de ataque."
	},
	"recommendation": {
		"en": "Remove or replace risky policies with least privilege alternatives.",
		"zh": "移除或替换高危策略，使用最小权限的替代方案。",
		"ja": "リスクのあるポリシーを削除するか、最小権限の代替案に置き換えます。",
		"de": "Entfernen oder ersetzen Sie riskante Richtlinien durch Alternativen mit geringsten Berechtigungen.",
		"es": "Elimine o reemplace políticas riesgosas con alternativas de menor privilegio.",
		"fr": "Supprimez ou remplacez les politiques risquées par des alternatives à privilèges minimaux.",
		"pt": "Remova ou substitua políticas arriscadas por alternativas de menor privilégio."
	},
	"resource_types": ["ALIYUN::RAM::User"]
}

risky_policies := [
	"AdministratorAccess",
	"*:*",
]

is_admin_policy(policy_name) if {
	policy_name == "AdministratorAccess"
}

is_admin_policy(policy_name) if {
	policy_name == "*"
}

has_risky_system_policy(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	some policy in system_policies
	is_admin_policy(policy)
}

has_risky_system_policy(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	some policy in system_policies
	policy in risky_policies
}

has_risky_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	is_admin_policy(policy_name)
}

has_risky_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name in risky_policies
}

has_risky_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_get_att_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	is_admin_policy(policy_name)
}

has_risky_policy_via_attachment(user_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToUser")
	user_name_val := helpers.get_property(resource, "UserName", "")
	helpers.is_get_att_referencing(user_name_val, user_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name in risky_policies
}

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	has_risky_system_policy(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": ["Properties", "PolicyAttachments", "System"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some user_name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	has_risky_policy_via_attachment(user_name)

	result := {
		"id": rule_meta.id,
		"resource_id": user_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
