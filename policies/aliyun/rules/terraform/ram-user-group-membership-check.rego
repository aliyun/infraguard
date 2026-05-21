package infraguard.rules.terraform.ram_user_group_membership_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-group-membership-check",
	"severity": "low",
	"name": {
		"en": "RAM User Group Membership Check",
		"zh": "RAM 用户组归属检测",
		"ja": "RAM ユーザーグループメンバーシップチェック",
		"de": "RAM-Benutzer Gruppenmitgliedschaftsprüfung",
		"es": "Verificación de Membresía de Grupo de Usuario RAM",
		"fr": "Vérification d'Appartenance au Groupe d'Utilisateur RAM",
		"pt": "Verificação de Associação ao Grupo de Usuário RAM"
	},
	"description": {
		"en": "Ensures that RAM users belong to at least one group for easier permission management.",
		"zh": "确保 RAM 用户属于至少一个用户组，以便于权限管理。",
		"ja": "RAM ユーザーが権限管理を容易にするために少なくとも 1 つのグループに属していることを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer zu mindestens einer Gruppe gehören, um die Berechtigungsverwaltung zu erleichtern.",
		"es": "Garantiza que los usuarios RAM pertenezcan al menos a un grupo para facilitar la gestión de permisos.",
		"fr": "Garantit que les utilisateurs RAM appartiennent à au moins un groupe pour faciliter la gestion des permissions.",
		"pt": "Garante que os usuários RAM pertençam a pelo menos um grupo para facilitar o gerenciamento de permissões."
	},
	"reason": {
		"en": "Managing permissions through groups is more efficient and less error-prone than managing individual user permissions.",
		"zh": "通过组管理权限比管理单个用户的权限更高效且更不容易出错。",
		"ja": "グループを通じて権限を管理することは、個々のユーザー権限を管理するよりも効率的で、エラーが発生しにくくなります。",
		"de": "Die Verwaltung von Berechtigungen über Gruppen ist effizienter und weniger fehleranfällig als die Verwaltung einzelner Benutzerberechtigungen.",
		"es": "Gestionar permisos a través de grupos es más eficiente y menos propenso a errores que gestionar permisos de usuarios individuales.",
		"fr": "Gérer les permissions via les groupes est plus efficace et moins sujet aux erreurs que la gestion des permissions des utilisateurs individuels.",
		"pt": "Gerenciar permissões através de grupos é mais eficiente e menos propenso a erros do que gerenciar permissões de usuários individuais."
	},
	"recommendation": {
		"en": "Add an alicloud_ram_group_membership resource to assign RAM users to groups.",
		"zh": "添加 alicloud_ram_group_membership 资源将 RAM 用户分配到用户组。",
		"ja": "alicloud_ram_group_membership リソースを追加して、RAM ユーザーをグループに割り当てます。",
		"de": "Fügen Sie eine alicloud_ram_group_membership-Ressource hinzu, um RAM-Benutzer Gruppen zuzuweisen.",
		"es": "Agregue un recurso alicloud_ram_group_membership para asignar usuarios RAM a grupos.",
		"fr": "Ajoutez une ressource alicloud_ram_group_membership pour assigner les utilisateurs RAM aux groupes.",
		"pt": "Adicione um recurso alicloud_ram_group_membership para atribuir usuários RAM a grupos."
	},
	"resource_types": ["alicloud_ram_user"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_user")
	not tf.has_resource_type("alicloud_ram_group_membership")
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
