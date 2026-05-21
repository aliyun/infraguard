package infraguard.rules.terraform.ram_role_no_product_admin_access

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-role-no-product-admin-access",
	"severity": "medium",
	"name": {
		"en": "RAM Role No Product Admin Access",
		"zh": "RAM 角色无超级管理员或某个云产品管理员权限",
		"ja": "RAM ロールに製品管理アクセスがない",
		"de": "RAM-Rolle Kein Produkt-Admin-Zugriff",
		"es": "El Rol RAM No Tiene Acceso de Administrador de Producto",
		"fr": "Le Rôle RAM N'a Pas d'Accès Administrateur Produit",
		"pt": "A Função RAM Não Tem Acesso de Administrador de Produto"
	},
	"description": {
		"en": "Ensures RAM roles do not have full administrative access or product administrator permissions.",
		"zh": "确保 RAM 角色未拥有管理员权限或者某个云产品的管理员权限。",
		"ja": "RAM ロールが完全な管理アクセスまたは製品管理者権限を持っていないことを確認します。",
		"de": "Stellt sicher, dass RAM-Rollen keinen vollständigen Administratorzugriff oder Produkt-Administratorberechtigungen haben.",
		"es": "Garantiza que los roles RAM no tengan acceso administrativo completo o permisos de administrador de producto.",
		"fr": "Garantit que les rôles RAM n'ont pas d'accès administratif complet ou de permissions d'administrateur de produit.",
		"pt": "Garante que as funções RAM não tenham acesso administrativo completo ou permissões de administrador de produto."
	},
	"reason": {
		"en": "Granting administrative access increases the risk of accidental or malicious configuration changes.",
		"zh": "授予管理权限会增加意外或恶意配置更改的风险。",
		"ja": "管理アクセスを付与すると、誤ったまたは悪意のある設定変更のリスクが増加します。",
		"de": "Die Gewährung von Administratorzugriff erhöht das Risiko versehentlicher oder böswilliger Konfigurationsänderungen.",
		"es": "Otorgar acceso administrativo aumenta el riesgo de cambios de configuración accidentales o maliciosos.",
		"fr": "Accorder un accès administratif augmente le risque de modifications de configuration accidentelles ou malveillantes.",
		"pt": "Conceder acesso administrativo aumenta o risco de alterações de configuração acidentais ou maliciosas."
	},
	"recommendation": {
		"en": "Set the max_session_duration attribute on the alicloud_ram_role resource to limit session duration and follow the principle of least privilege.",
		"zh": "在 alicloud_ram_role 资源上设置 max_session_duration 属性以限制会话时长，并遵循最小权限原则。",
		"ja": "alicloud_ram_role リソースで max_session_duration 属性を設定してセッション時間を制限し、最小権限の原則に従います。",
		"de": "Setzen Sie das max_session_duration-Attribut auf der alicloud_ram_role-Ressource, um die Sitzungsdauer zu begrenzen und dem Prinzip der geringsten Berechtigung zu folgen.",
		"es": "Establezca el atributo max_session_duration en el recurso alicloud_ram_role para limitar la duración de la sesión y seguir el principio de privilegio mínimo.",
		"fr": "Définissez l'attribut max_session_duration sur la ressource alicloud_ram_role pour limiter la durée de session et suivre le principe du moindre privilège.",
		"pt": "Defina o atributo max_session_duration no recurso alicloud_ram_role para limitar a duração da sessão e seguir o princípio do menor privilégio."
	},
	"resource_types": ["alicloud_ram_role"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_role")
	max_duration := tf.get_attribute(resource, "max_session_duration", 0)
	not max_duration > 0
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_role.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
