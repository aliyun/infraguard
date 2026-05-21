package infraguard.rules.terraform.ram_group_in_use_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Add an alicloud_ram_group_membership resource for members, or remove the unused group.",
		"zh": "添加 alicloud_ram_group_membership 资源以添加成员，或移除未使用的组。",
		"ja": "メンバー用の alicloud_ram_group_membership リソースを追加するか、未使用のグループを削除します。",
		"de": "Fügen Sie eine alicloud_ram_group_membership-Ressource für Mitglieder hinzu oder entfernen Sie die ungenutzte Gruppe.",
		"es": "Agregue un recurso alicloud_ram_group_membership para miembros, o elimine el grupo no utilizado.",
		"fr": "Ajoutez une ressource alicloud_ram_group_membership pour les membres, ou supprimez le groupe non utilisé.",
		"pt": "Adicione um recurso alicloud_ram_group_membership para membros, ou remova o grupo não utilizado."
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

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_group")
	not tf.has_resource_type("alicloud_ram_group_policy_attachment")
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
