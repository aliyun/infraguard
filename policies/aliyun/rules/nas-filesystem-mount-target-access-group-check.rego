package infraguard.rules.aliyun.nas_filesystem_mount_target_access_group_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "nas-filesystem-mount-target-access-group-check",
	"severity": "medium",
	"name": {
		"en": "NAS Mount Target Access Group Check",
		"zh": "NAS 挂载点禁用默认权限组",
		"ja": "NAS マウントターゲットアクセスグループチェック",
		"de": "NAS-Mount-Ziel Zugriffsgruppenprüfung",
		"es": "Verificación de Grupo de Acceso de Objetivo de Montaje NAS",
		"fr": "Vérification du Groupe d'Accès de Cible de Montage NAS",
		"pt": "Verificação de Grupo de Acesso do Alvo de Montagem NAS"
	},
	"description": {
		"en": "Ensures NAS mount targets do not use the 'DEFAULT_VPC_GROUP_NAME'.",
		"zh": "确保 NAS 挂载点未使用'DEFAULT_VPC_GROUP_NAME'。",
		"ja": "NAS マウントターゲットが 'DEFAULT_VPC_GROUP_NAME' を使用していないことを確認します。",
		"de": "Stellt sicher, dass NAS-Mount-Ziele 'DEFAULT_VPC_GROUP_NAME' nicht verwenden.",
		"es": "Garantiza que los objetivos de montaje NAS no usen 'DEFAULT_VPC_GROUP_NAME'.",
		"fr": "Garantit que les cibles de montage NAS n'utilisent pas 'DEFAULT_VPC_GROUP_NAME'.",
		"pt": "Garante que os alvos de montagem NAS não usem 'DEFAULT_VPC_GROUP_NAME'."
	},
	"reason": {
		"en": "The default access group may have overly permissive rules.",
		"zh": "默认权限组可能拥有过于宽松的规则。",
		"ja": "デフォルトのアクセスグループには過度に許可的なルールがある可能性があります。",
		"de": "Die Standard-Zugriffsgruppe kann übermäßig permissive Regeln haben.",
		"es": "El grupo de acceso predeterminado puede tener reglas excesivamente permisivas.",
		"fr": "Le groupe d'accès par défaut peut avoir des règles trop permissives.",
		"pt": "O grupo de acesso padrão pode ter regras excessivamente permissivas."
	},
	"recommendation": {
		"en": "Use a custom access group with restricted rules for NAS mount targets.",
		"zh": "为 NAS 挂载点使用规则受限的自定义权限组。",
		"ja": "NAS マウントターゲットには制限されたルールを持つカスタムアクセスグループを使用します。",
		"de": "Verwenden Sie eine benutzerdefinierte Zugriffsgruppe mit eingeschränkten Regeln für NAS-Mount-Ziele.",
		"es": "Use un grupo de acceso personalizado con reglas restringidas para objetivos de montaje NAS.",
		"fr": "Utilisez un groupe d'accès personnalisé avec des règles restreintes pour les cibles de montage NAS.",
		"pt": "Use um grupo de acesso personalizado com regras restritas para alvos de montagem NAS."
	},
	"resource_types": ["ALIYUN::NAS::MountTarget"]
}

is_compliant(resource) if {
	group := helpers.get_property(resource, "AccessGroupName", "DEFAULT_VPC_GROUP_NAME")
	group != "DEFAULT_VPC_GROUP_NAME"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAS::MountTarget")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AccessGroupName"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
