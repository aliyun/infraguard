package infraguard.rules.aliyun.root_has_specified_role

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "root-has-specified-role",
	"severity": "low",
	"name": {
		"en": "Root Account Has Specified Role",
		"zh": "主账号具有指定的角色",
		"ja": "ルートアカウントに指定されたロールがある",
		"de": "Root-Konto hat angegebene Rolle",
		"es": "La Cuenta Raíz Tiene Rol Especificado",
		"fr": "Le Compte Racine a un Rôle Spécifié",
		"pt": "A Conta Raiz Tem Função Especificada"
	},
	"description": {
		"en": "Ensures that the root account has a specified RAM role for governance and management.",
		"zh": "确保主账号具有用于治理和管理的指定 RAM 角色。",
		"ja": "ルートアカウントがガバナンスと管理のための指定された RAM ロールを持っていることを確認します。",
		"de": "Stellt sicher, dass das Root-Konto eine angegebene RAM-Rolle für Governance und Verwaltung hat.",
		"es": "Garantiza que la cuenta raíz tenga un rol RAM especificado para gobernanza y gestión.",
		"fr": "Garantit que le compte racine a un rôle RAM spécifié pour la gouvernance et la gestion.",
		"pt": "Garante que a conta raiz tenha uma função RAM especificada para governança e gerenciamento."
	},
	"reason": {
		"en": "Specific roles are required for cloud governance and management tools to function correctly.",
		"zh": "云治理和管理工具需要特定的角色才能正常运行。",
		"ja": "クラウドガバナンスと管理ツールが正常に機能するには、特定のロールが必要です。",
		"de": "Spezifische Rollen sind erforderlich, damit Cloud-Governance- und Verwaltungstools korrekt funktionieren.",
		"es": "Se requieren roles específicos para que las herramientas de gobernanza y gestión en la nube funcionen correctamente.",
		"fr": "Des rôles spécifiques sont requis pour que les outils de gouvernance et de gestion cloud fonctionnent correctement.",
		"pt": "Funções específicas são necessárias para que as ferramentas de governança e gerenciamento em nuvem funcionem corretamente."
	},
	"recommendation": {
		"en": "Create and assign the specified RAM role to the root account.",
		"zh": "创建并为主账号分配指定的 RAM 角色。",
		"ja": "指定された RAM ロールを作成し、ルートアカウントに割り当てます。",
		"de": "Erstellen und weisen Sie die angegebene RAM-Rolle dem Root-Konto zu.",
		"es": "Cree y asigne el rol RAM especificado a la cuenta raíz.",
		"fr": "Créez et assignez le rôle RAM spécifié au compte racine.",
		"pt": "Crie e atribua a função RAM especificada à conta raiz."
	},
	"resource_types": ["ALIYUN::RAM::User"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	name == "root"
	not helpers.has_property(resource, "SpecifiedRole")
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
