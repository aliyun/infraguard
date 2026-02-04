package infraguard.rules.aliyun.ram_group_in_use_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-group-in-use-check",
	"severity": "low",
	"name": {
		"en": "RAM Group In Use Check",
		"zh": "RAM 用户组使用检测",
		"ja": "RAM グループ使用中チェック",
		"de": "RAM-Gruppe In Verwendung Prüfung",
		"es": "Verificación de Grupo RAM en Uso",
		"fr": "Vérification du Groupe RAM en Utilisation",
		"pt": "Verificação de Grupo RAM em Uso"
	},
	"description": {
		"en": "Ensures RAM groups are not idle - must have at least one member and at least one attached policy.",
		"zh": "确保 RAM 用户组处于使用状态 - 必须至少包含一个成员且绑定了至少一个权限策略。",
		"ja": "RAM グループがアイドル状態でないことを確認します - 少なくとも 1 つのメンバーと少なくとも 1 つのアタッチされたポリシーが必要です。",
		"de": "Stellt sicher, dass RAM-Gruppen nicht im Leerlauf sind - müssen mindestens ein Mitglied und mindestens eine angehängte Richtlinie haben.",
		"es": "Garantiza que los grupos RAM no estén inactivos - deben tener al menos un miembro y al menos una política adjunta.",
		"fr": "Garantit que les groupes RAM ne sont pas inactifs - doivent avoir au moins un membre et au moins une politique attachée.",
		"pt": "Garante que os grupos RAM não estejam ociosos - devem ter pelo menos um membro e pelo menos uma política anexada."
	},
	"reason": {
		"en": "Idle RAM groups increase management complexity and should be removed.",
		"zh": "闲置的 RAM 用户组会增加管理复杂性，应予以移除。",
		"ja": "アイドル状態の RAM グループは管理の複雑さを増し、削除する必要があります。",
		"de": "Leerlaufende RAM-Gruppen erhöhen die Verwaltungskomplexität und sollten entfernt werden.",
		"es": "Los grupos RAM inactivos aumentan la complejidad de gestión y deben eliminarse.",
		"fr": "Les groupes RAM inactifs augmentent la complexité de gestion et doivent être supprimés.",
		"pt": "Grupos RAM ociosos aumentam a complexidade de gerenciamento e devem ser removidos."
	},
	"recommendation": {
		"en": "Add members to the group or attach policies, or remove the unused group.",
		"zh": "向该组添加成员或绑定策略，或移除未使用的组。",
		"ja": "グループにメンバーを追加するか、ポリシーをアタッチするか、未使用のグループを削除します。",
		"de": "Fügen Sie Mitglieder zur Gruppe hinzu oder hängen Sie Richtlinien an, oder entfernen Sie die ungenutzte Gruppe.",
		"es": "Agregue miembros al grupo o adjunte políticas, o elimine el grupo no utilizado.",
		"fr": "Ajoutez des membres au groupe ou attachez des politiques, ou supprimez le groupe non utilisé.",
		"pt": "Adicione membros ao grupo ou anexe políticas, ou remova o grupo não utilizado."
	},
	"resource_types": ["ALIYUN::RAM::Group"]
}

has_member(group_logical_id, group_resource) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::UserToGroupAddition")
	val := helpers.get_property(resource, "GroupName", "")
	helpers.is_referencing(val, group_logical_id)
}

has_member(group_logical_id, group_resource) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::UserToGroupAddition")
	val := helpers.get_property(resource, "GroupName", "")
	helpers.is_get_att_referencing(val, group_logical_id)
}

has_member(group_logical_id, group_resource) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::UserToGroupAddition")
	val := helpers.get_property(resource, "GroupName", "")
	actual_name := helpers.get_property(group_resource, "GroupName", "")
	val == actual_name
}

has_policy_inline(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	count(system_policies) > 0
}

has_policy_inline(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	custom_policies := object.get(policy_attachments, "Custom", [])
	count(custom_policies) > 0
}

has_policy_via_attachment(group_logical_id, group_resource) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToGroup")
	group_name_val := helpers.get_property(resource, "GroupName", "")
	helpers.is_referencing(group_name_val, group_logical_id)
}

has_policy_via_attachment(group_logical_id, group_resource) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToGroup")
	group_name_val := helpers.get_property(resource, "GroupName", "")
	helpers.is_get_att_referencing(group_name_val, group_logical_id)
}

has_policy_via_attachment(group_logical_id, group_resource) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToGroup")
	group_name_val := helpers.get_property(resource, "GroupName", "")
	actual_name := helpers.get_property(group_resource, "GroupName", "")
	group_name_val == actual_name
}

deny contains result if {
	some group_name, resource in helpers.resources_by_type("ALIYUN::RAM::Group")

	not has_member(group_name, resource)
	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some group_name, resource in helpers.resources_by_type("ALIYUN::RAM::Group")

	not has_policy_inline(resource)
	not has_policy_via_attachment(group_name, resource)
	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties", "PolicyAttachments"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
