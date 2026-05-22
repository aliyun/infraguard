package infraguard.rules.terraform.ram_user_no_product_admin_access

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-no-product-admin-access",
	"severity": "medium",
	"name": {
		"en": "RAM User No Product Administrative Access",
		"zh": "RAM 用户没有产品管理权限",
		"ja": "RAM ユーザーに製品管理アクセスなし",
		"de": "RAM-Benutzer kein Produkt-Administrativzugriff",
		"es": "Usuario RAM Sin Acceso Administrativo de Producto",
		"fr": "Utilisateur RAM Sans Accès Administratif au Produit",
		"pt": "Usuário RAM Sem Acesso Administrativo ao Produto"
	},
	"description": {
		"en": "Ensures that RAM users do not have full administrative access to cloud products unless necessary.",
		"zh": "确保 RAM 用户未被授予对云产品的完全管理权限，除非必要。",
		"ja": "必要でない限り、RAM ユーザーがクラウド製品への完全な管理アクセスを持たないことを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer keinen vollständigen administrativen Zugriff auf Cloud-Produkte haben, es sei denn, es ist notwendig.",
		"es": "Garantiza que los usuarios RAM no tengan acceso administrativo completo a los productos en la nube a menos que sea necesario.",
		"fr": "Garantit que les utilisateurs RAM n'ont pas d'accès administratif complet aux produits cloud sauf si nécessaire.",
		"pt": "Garante que os usuários RAM não tenham acesso administrativo completo aos produtos em nuvem, a menos que seja necessário."
	},
	"reason": {
		"en": "Granting administrative access to all users increases the risk of accidental or malicious configuration changes.",
		"zh": "向所有用户授予管理权限会增加意外或恶意配置更改的风险。",
		"ja": "すべてのユーザーに管理アクセスを付与すると、偶発的または悪意のある設定変更のリスクが増加します。",
		"de": "Die Gewährung von administrativem Zugriff für alle Benutzer erhöht das Risiko versehentlicher oder böswilliger Konfigurationsänderungen.",
		"es": "Otorgar acceso administrativo a todos los usuarios aumenta el riesgo de cambios de configuración accidentales o maliciosos.",
		"fr": "Accorder l'accès administratif à tous les utilisateurs augmente le risque de modifications de configuration accidentelles ou malveillantes.",
		"pt": "Conceder acesso administrativo a todos os usuários aumenta o risco de alterações acidentais ou maliciosas na configuração."
	},
	"recommendation": {
		"en": "Remove FullAccess policies from alicloud_ram_user_policy_attachment and follow the principle of least privilege.",
		"zh": "从 alicloud_ram_user_policy_attachment 中移除 FullAccess 策略，遵循最小权限原则。",
		"ja": "alicloud_ram_user_policy_attachment から FullAccess ポリシーを削除し、最小権限の原則に従います。",
		"de": "Entfernen Sie FullAccess-Richtlinien aus alicloud_ram_user_policy_attachment und folgen Sie dem Prinzip der geringsten Berechtigung.",
		"es": "Elimine las políticas FullAccess de alicloud_ram_user_policy_attachment y siga el principio de menor privilegio.",
		"fr": "Supprimez les politiques FullAccess de alicloud_ram_user_policy_attachment et suivez le principe du moindre privilège.",
		"pt": "Remova as políticas FullAccess de alicloud_ram_user_policy_attachment e siga o princípio do menor privilégio."
	},
	"resource_types": ["alicloud_ram_user_policy_attachment"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_user_policy_attachment")
	policy_name := tf.get_attribute(resource, "policy_name", "")
	contains(policy_name, "FullAccess")
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_user_policy_attachment.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
