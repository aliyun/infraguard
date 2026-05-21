package infraguard.rules.terraform.nas_filesystem_mount_target_access_group_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "nas-filesystem-mount-target-access-group-check",
	"severity": "medium",
	"name": {
		"en": "NAS Mount Target Access Group Check",
		"zh": "NAS 挂载点禁用默认权限组",
		"ja": "NAS マウントターゲットアクセスグループチェック",
		"de": "NAS-Mountziel-Zugriffsgruppen-Prüfung",
		"es": "Verificación del Grupo de Acceso del Objetivo de Montaje NAS",
		"fr": "Vérification du Groupe d'Accès de la Cible de Montage NAS",
		"pt": "Verificação do Grupo de Acesso do Alvo de Montagem NAS"
	},
	"description": {
		"en": "Ensures that NAS mount targets do not use the default VPC access group (DEFAULT_VPC_GROUP_NAME).",
		"zh": "确保 NAS 挂载点未使用默认 VPC 权限组（DEFAULT_VPC_GROUP_NAME）。",
		"ja": "NAS マウントターゲットがデフォルトの VPC アクセスグループ（DEFAULT_VPC_GROUP_NAME）を使用していないことを確認します。",
		"de": "Stellt sicher, dass NAS-Mountziele nicht die Standard-VPC-Zugriffsgruppe (DEFAULT_VPC_GROUP_NAME) verwenden.",
		"es": "Garantiza que los objetivos de montaje NAS no usen el grupo de acceso VPC predeterminado (DEFAULT_VPC_GROUP_NAME).",
		"fr": "Garantit que les cibles de montage NAS n'utilisent pas le groupe d'accès VPC par défaut (DEFAULT_VPC_GROUP_NAME).",
		"pt": "Garante que os alvos de montagem NAS não usem o grupo de acesso VPC padrão (DEFAULT_VPC_GROUP_NAME)."
	},
	"reason": {
		"en": "The NAS mount target uses the default VPC access group, which may have overly permissive settings.",
		"zh": "NAS 挂载点使用了默认 VPC 权限组，可能具有过于宽松的设置。",
		"ja": "NAS マウントターゲットがデフォルトの VPC アクセスグループを使用しており、過度に許可的な設定になっている可能性があります。",
		"de": "Das NAS-Mountziel verwendet die Standard-VPC-Zugriffsgruppe, die möglicherweise zu freizügige Einstellungen hat.",
		"es": "El objetivo de montaje NAS usa el grupo de acceso VPC predeterminado, que puede tener configuraciones excesivamente permisivas.",
		"fr": "La cible de montage NAS utilise le groupe d'accès VPC par défaut, qui peut avoir des paramètres trop permissifs.",
		"pt": "O alvo de montagem NAS usa o grupo de acesso VPC padrão, que pode ter configurações excessivamente permissivas."
	},
	"recommendation": {
		"en": "Create and assign a custom access group with appropriate access rules instead of using DEFAULT_VPC_GROUP_NAME.",
		"zh": "创建并分配具有适当访问规则的自定义权限组，而不是使用 DEFAULT_VPC_GROUP_NAME。",
		"ja": "DEFAULT_VPC_GROUP_NAME を使用する代わりに、適切なアクセスルールを持つカスタムアクセスグループを作成して割り当てます。",
		"de": "Erstellen und weisen Sie eine benutzerdefinierte Zugriffsgruppe mit geeigneten Zugriffsregeln zu, anstatt DEFAULT_VPC_GROUP_NAME zu verwenden.",
		"es": "Cree y asigne un grupo de acceso personalizado con reglas de acceso apropiadas en lugar de usar DEFAULT_VPC_GROUP_NAME.",
		"fr": "Créez et attribuez un groupe d'accès personnalisé avec des règles d'accès appropriées au lieu d'utiliser DEFAULT_VPC_GROUP_NAME.",
		"pt": "Crie e atribua um grupo de acesso personalizado com regras de acesso apropriadas em vez de usar DEFAULT_VPC_GROUP_NAME."
	},
	"resource_types": ["alicloud_nas_mount_target"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_nas_mount_target")
	access_group := tf.get_attribute(resource, "access_group_name", "")
	access_group == "DEFAULT_VPC_GROUP_NAME"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_nas_mount_target.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
