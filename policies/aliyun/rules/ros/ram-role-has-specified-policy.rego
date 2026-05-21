package infraguard.rules.aliyun.ram_role_has_specified_policy

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-role-has-specified-policy",
	"severity": "medium",
	"name": {
		"en": "RAM Role Has Specified Policy",
		"zh": "RAM 角色绑定指定策略检测",
		"ja": "RAM ロールに指定されたポリシーがある",
		"de": "RAM-Rolle hat angegebene Richtlinie",
		"es": "El Rol RAM Tiene Política Especificada",
		"fr": "Le Rôle RAM a une Politique Spécifiée",
		"pt": "Função RAM Tem Política Especificada"
	},
	"description": {
		"en": "Ensures RAM roles have the specified policies attached.",
		"zh": "确保 RAM 角色绑定了符合参数条件的权限策略。",
		"ja": "RAM ロールに指定されたポリシーがアタッチされていることを確認します。",
		"de": "Stellt sicher, dass RAM-Rollen die angegebenen Richtlinien angehängt haben.",
		"es": "Garantiza que los roles RAM tengan las políticas especificadas adjuntas.",
		"fr": "Garantit que les rôles RAM ont les politiques spécifiées attachées.",
		"pt": "Garante que as funções RAM tenham as políticas especificadas anexadas."
	},
	"reason": {
		"en": "Proper policy attachment ensures roles have necessary permissions.",
		"zh": "正确绑定策略可确保角色具有必要的权限。",
		"ja": "適切なポリシーのアタッチにより、ロールに必要な権限があることが保証されます。",
		"de": "Die ordnungsgemäße Anheftung von Richtlinien stellt sicher, dass Rollen die erforderlichen Berechtigungen haben.",
		"es": "La adjunción adecuada de políticas garantiza que los roles tengan los permisos necesarios.",
		"fr": "L'attachement approprié des politiques garantit que les rôles ont les permissions nécessaires.",
		"pt": "O anexo adequado de políticas garante que as funções tenham as permissões necessárias."
	},
	"recommendation": {
		"en": "Attach the required policies to the RAM role.",
		"zh": "向 RAM 角色绑定所需的策略。",
		"ja": "必要なポリシーを RAM ロールにアタッチします。",
		"de": "Hängen Sie die erforderlichen Richtlinien an die RAM-Rolle an.",
		"es": "Adjunte las políticas requeridas al rol RAM.",
		"fr": "Attachez les politiques requises au rôle RAM.",
		"pt": "Anexe as políticas necessárias à função RAM."
	},
	"resource_types": ["ALIYUN::RAM::Role"]
}

has_policy_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	helpers.is_referencing(role_name_val, role_name)
}

has_policy_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	helpers.is_get_att_referencing(role_name_val, role_name)
}

has_policy_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	role_resource := helpers.resources_by_type("ALIYUN::RAM::Role")[role_name]
	actual_name := helpers.get_property(role_resource, "RoleName", role_name)
	role_name_val == actual_name
}

deny contains result if {
	some role_name, resource in helpers.resources_by_type("ALIYUN::RAM::Role")

	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	custom_policies := object.get(policy_attachments, "Custom", [])

	count(system_policies) == 0
	count(custom_policies) == 0
	not has_policy_via_attachment(role_name)

	result := {
		"id": rule_meta.id,
		"resource_id": role_name,
		"violation_path": ["Properties", "PolicyAttachments"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
