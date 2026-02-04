package infraguard.rules.aliyun.ram_user_group_membership_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ram-user-group-membership-check",
	"name": {
		"en": "RAM User Group Membership Check",
		"zh": "RAM 用户组归属检测",
		"ja": "RAM ユーザーグループメンバーシップチェック",
		"de": "RAM-Benutzer Gruppenmitgliedschaftsprüfung",
		"es": "Verificación de Membresía de Grupo de Usuario RAM",
		"fr": "Vérification d'Appartenance au Groupe d'Utilisateur RAM",
		"pt": "Verificação de Associação ao Grupo de Usuário RAM",
	},
	"severity": "low",
	"description": {
		"en": "Ensures that RAM users belong to at least one group for easier permission management.",
		"zh": "确保 RAM 用户属于至少一个用户组，以便于权限管理。",
		"ja": "RAM ユーザーが権限管理を容易にするために少なくとも 1 つのグループに属していることを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer zu mindestens einer Gruppe gehören, um die Berechtigungsverwaltung zu erleichtern.",
		"es": "Garantiza que los usuarios RAM pertenezcan al menos a un grupo para facilitar la gestión de permisos.",
		"fr": "Garantit que les utilisateurs RAM appartiennent à au moins un groupe pour faciliter la gestion des permissions.",
		"pt": "Garante que os usuários RAM pertençam a pelo menos um grupo para facilitar o gerenciamento de permissões.",
	},
	"reason": {
		"en": "Managing permissions through groups is more efficient and less error-prone than managing individual user permissions.",
		"zh": "通过组管理权限比管理单个用户的权限更高效且更不容易出错。",
		"ja": "グループを通じて権限を管理することは、個々のユーザー権限を管理するよりも効率的で、エラーが発生しにくくなります。",
		"de": "Die Verwaltung von Berechtigungen über Gruppen ist effizienter und weniger fehleranfällig als die Verwaltung einzelner Benutzerberechtigungen.",
		"es": "Gestionar permisos a través de grupos es más eficiente y menos propenso a errores que gestionar permisos de usuarios individuales.",
		"fr": "Gérer les permissions via les groupes est plus efficace et moins sujet aux erreurs que la gestion des permissions des utilisateurs individuels.",
		"pt": "Gerenciar permissões através de grupos é mais eficiente e menos propenso a erros do que gerenciar permissões de usuários individuais.",
	},
	"recommendation": {
		"en": "Assign RAM users to relevant user groups.",
		"zh": "将 RAM 用户分配到相关的用户组中。",
		"ja": "RAM ユーザーを関連するユーザーグループに割り当てます。",
		"de": "Weisen Sie RAM-Benutzer relevanten Benutzergruppen zu.",
		"es": "Asigne usuarios RAM a grupos de usuarios relevantes.",
		"fr": "Assignez les utilisateurs RAM aux groupes d'utilisateurs pertinents.",
		"pt": "Atribua usuários RAM a grupos de usuários relevantes.",
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	# Conceptual check for group membership
	not helpers.has_property(resource, "Groups")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
