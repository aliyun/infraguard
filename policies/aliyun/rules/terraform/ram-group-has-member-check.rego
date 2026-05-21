package infraguard.rules.terraform.ram_group_has_member_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-group-has-member-check",
	"severity": "low",
	"name": {
		"en": "RAM Group Has Member",
		"zh": "识别无成员的空 RAM 用户组",
		"ja": "RAM グループにメンバーがある",
		"de": "RAM-Gruppe hat Mitglied",
		"es": "El Grupo RAM Tiene Miembro",
		"fr": "Le Groupe RAM a un Membre",
		"pt": "O Grupo RAM Tem Membro"
	},
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
		"en": "Add an alicloud_ram_group_membership resource referencing this group, or remove the empty group.",
		"zh": "添加引用该组的 alicloud_ram_group_membership 资源，或移除此空组。",
		"ja": "このグループを参照する alicloud_ram_group_membership リソースを追加するか、空のグループを削除します。",
		"de": "Fügen Sie eine alicloud_ram_group_membership-Ressource hinzu, die auf diese Gruppe verweist, oder entfernen Sie die leere Gruppe.",
		"es": "Agregue un recurso alicloud_ram_group_membership que haga referencia a este grupo, o elimine el grupo vacío.",
		"fr": "Ajoutez une ressource alicloud_ram_group_membership référençant ce groupe, ou supprimez le groupe vide.",
		"pt": "Adicione um recurso alicloud_ram_group_membership referenciando este grupo, ou remova o grupo vazio."
	},
	"resource_types": ["alicloud_ram_group"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_group")
	not tf.has_resource_type("alicloud_ram_group_membership")
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_group.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
