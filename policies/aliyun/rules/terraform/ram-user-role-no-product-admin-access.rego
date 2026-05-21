package infraguard.rules.terraform.ram_user_role_no_product_admin_access

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-role-no-product-admin-access",
	"severity": "high",
	"name": {
		"en": "RAM User Role No Product Admin Access",
		"zh": "ram 用户定义的角色不包括产品管理权限",
		"ja": "RAM ユーザーロールに製品管理アクセスがない",
		"de": "RAM-Benutzerrolle Kein Produkt-Admin-Zugriff",
		"es": "El Rol de Usuario RAM No Tiene Acceso de Administrador de Producto",
		"fr": "Le Rôle d'Utilisateur RAM N'a Pas d'Accès Administrateur Produit",
		"pt": "A Função de Usuário RAM Não Tem Acesso de Administrador de Produto"
	},
	"description": {
		"en": "Ensures RAM role policy attachments do not grant product administrative permissions.",
		"zh": "确保 RAM 角色策略绑定未授予产品管理员权限。",
		"ja": "RAM ロールポリシーのアタッチメントが製品管理権限を付与していないことを確認します。",
		"de": "Stellt sicher, dass RAM-Rollenrichtlinien-Anhänge keine Produkt-Administratorberechtigungen gewähren.",
		"es": "Garantiza que las adjunciones de políticas de rol RAM no otorguen permisos administrativos de producto.",
		"fr": "Garantit que les attachements de politiques de rôle RAM n'accordent pas de permissions administratives de produit.",
		"pt": "Garante que os anexos de políticas de função RAM não concedam permissões administrativas de produto."
	},
	"reason": {
		"en": "Custom roles with admin permissions increase security risks.",
		"zh": "具有管理权限的自定义角色会增加安全风险。",
		"ja": "管理権限を持つカスタムロールはセキュリティリスクを増加させます。",
		"de": "Benutzerdefinierte Rollen mit Admin-Berechtigungen erhöhen die Sicherheitsrisiken.",
		"es": "Los roles personalizados con permisos de administrador aumentan los riesgos de seguridad.",
		"fr": "Les rôles personnalisés avec des permissions d'administrateur augmentent les risques de sécurité.",
		"pt": "Funções personalizadas com permissões de administrador aumentam os riscos de segurança."
	},
	"recommendation": {
		"en": "Remove FullAccess policies from alicloud_ram_role_policy_attachment and use least privilege alternatives.",
		"zh": "从 alicloud_ram_role_policy_attachment 中移除 FullAccess 策略，使用最小权限的替代方案。",
		"ja": "alicloud_ram_role_policy_attachment から FullAccess ポリシーを削除し、最小権限の代替案を使用します。",
		"de": "Entfernen Sie FullAccess-Richtlinien aus alicloud_ram_role_policy_attachment und verwenden Sie Alternativen mit geringsten Berechtigungen.",
		"es": "Elimine las políticas FullAccess de alicloud_ram_role_policy_attachment y use alternativas de menor privilegio.",
		"fr": "Supprimez les politiques FullAccess de alicloud_ram_role_policy_attachment et utilisez des alternatives à privilèges minimaux.",
		"pt": "Remova as políticas FullAccess de alicloud_ram_role_policy_attachment e use alternativas de menor privilégio."
	},
	"resource_types": ["alicloud_ram_role_policy_attachment"],
	"iac_type": "terraform"
}

is_admin_policy(policy_name) if {
	policy_name == "AdministratorAccess"
}

is_admin_policy(policy_name) if {
	contains(policy_name, "FullAccess")
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_role_policy_attachment")
	policy_name := tf.get_attribute(resource, "policy_name", "")
	not tf.is_unknown(policy_name)
	is_admin_policy(policy_name)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_role_policy_attachment.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
