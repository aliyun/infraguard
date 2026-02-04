package infraguard.rules.aliyun.ram_group_has_member_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-group-has-member-check",
	"name": {
		"en": "RAM Group Has Member",
		"zh": "识别无成员的空 RAM 用户组",
		"ja": "RAM グループにメンバーがある",
		"de": "RAM-Gruppe hat Mitglied",
		"es": "El Grupo RAM Tiene Miembro",
		"fr": "Le Groupe RAM a un Membre",
		"pt": "O Grupo RAM Tem Membro"
	},
	"severity": "low",
	"description": {
		"en": "Ensures RAM groups have at least one member.",
		"zh": "确保 RAM 用户组至少包含一名成员。",
		"ja": "RAM グループに少なくとも 1 人のメンバーがいることを確認します。",
		"de": "Stellt sicher, dass RAM-Gruppen mindestens ein Mitglied haben.",
		"es": "Garantiza que los grupos RAM tengan al menos un miembro.",
		"fr": "Garantit que les groupes RAM ont au moins un membre.",
		"pt": "Garante que os grupos RAM tenham pelo menos um membro."
	},
	"reason": {
		"en": "Empty groups are often unused and should be removed to maintain a clean environment.",
		"zh": "空的用户组通常处于闲置状态，应予以移除以保持环境整洁。",
		"ja": "空のグループは使用されていないことが多く、環境をクリーンに保つために削除する必要があります。",
		"de": "Leere Gruppen werden oft nicht verwendet und sollten entfernt werden, um eine saubere Umgebung zu erhalten.",
		"es": "Los grupos vacíos a menudo no se usan y deben eliminarse para mantener un entorno limpio.",
		"fr": "Les groupes vides sont souvent inutilisés et doivent être supprimés pour maintenir un environnement propre.",
		"pt": "Grupos vazios geralmente não são usados e devem ser removidos para manter um ambiente limpo."
	},
	"recommendation": {
		"en": "Add members to the group or remove the empty group.",
		"zh": "向该组添加成员，或移除此空组。",
		"ja": "グループにメンバーを追加するか、空のグループを削除します。",
		"de": "Fügen Sie Mitglieder zur Gruppe hinzu oder entfernen Sie die leere Gruppe.",
		"es": "Agregue miembros al grupo o elimine el grupo vacío.",
		"fr": "Ajoutez des membres au groupe ou supprimez le groupe vide.",
		"pt": "Adicione membros ao grupo ou remova o grupo vazio."
	},
	"resource_types": ["ALIYUN::RAM::Group"],
}

has_members(group_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::UserToGroupAddition")
	helpers.is_referencing(helpers.get_property(resource, "GroupName", ""), group_name)
}

deny contains result if {
	some group_name, resource in helpers.resources_by_type("ALIYUN::RAM::Group")

	# Check if this group is referenced in any UserToGroupAddition
	not has_members(group_name)
	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
