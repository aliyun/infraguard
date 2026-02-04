package infraguard.rules.aliyun.ram_policy_in_use_check

import data.infraguard.helpers
import rego.v1

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
		"en": "Attach the policy to users, groups, or roles, or remove the unused policy.",
		"zh": "将策略绑定到用户、组或角色，或移除未使用的策略。",
		"ja": "ポリシーをユーザー、グループ、またはロールにアタッチするか、未使用のポリシーを削除します。",
		"de": "Hängen Sie die Richtlinie an Benutzer, Gruppen oder Rollen an oder entfernen Sie die ungenutzte Richtlinie.",
		"es": "Adjunte la política a usuarios, grupos o roles, o elimine la política no utilizada.",
		"fr": "Attachez la politique aux utilisateurs, groupes ou rôles, ou supprimez la politique non utilisée.",
		"pt": "Anexe a política a usuários, grupos ou funções, ou remova a política não utilizada."
	},
	"resource_types": ["ALIYUN::RAM::ManagedPolicy"]
}

deny contains result if {
	some policy_logical_id, resource in helpers.resources_by_type("ALIYUN::RAM::ManagedPolicy")

	# Get actual policy name if available, otherwise use logical ID
	policy_name := helpers.get_property(resource, "PolicyName", policy_logical_id)

	not is_policy_attached(policy_logical_id, policy_name)
	result := {
		"id": rule_meta.id,
		"resource_id": policy_logical_id,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

is_policy_attached(policy_logical_id, policy_name) if {
	some type in ["ALIYUN::RAM::AttachPolicyToUser", "ALIYUN::RAM::AttachPolicyToGroup", "ALIYUN::RAM::AttachPolicyToRole"]
	some name, resource in helpers.resources_by_type(type)

	# Check if attached policy matches
	val := helpers.get_property(resource, "PolicyName", "")

	# Check match (Ref, GetAtt, or Name)
	matches_policy(val, policy_logical_id, policy_name)
}

is_policy_attached(policy_logical_id, policy_name) if {
	some type in ["ALIYUN::RAM::Role", "ALIYUN::RAM::User", "ALIYUN::RAM::Group"]
	some name, resource in helpers.resources_by_type(type)
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})

	# Check System and Custom policies
	# System policies usually don't match custom policy resources, but Custom might
	custom_policies := object.get(policy_attachments, "Custom", [])
	some p in custom_policies
	matches_policy(p, policy_logical_id, policy_name)
}

# Helper to check if value matches policy
matches_policy(val, policy_logical_id, policy_name) if {
	helpers.is_referencing(val, policy_logical_id)
}

matches_policy(val, policy_logical_id, policy_name) if {
	helpers.is_get_att_referencing(val, policy_logical_id)
}

matches_policy(val, policy_logical_id, policy_name) if {
	val == policy_name
}
