package infraguard.rules.aliyun.ram_user_no_product_admin_access

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ram-user-no-product-admin-access",
	"name": {
		"en": "RAM User No Product Administrative Access",
		"zh": "RAM 用户没有产品管理权限",
		"ja": "RAM ユーザーに製品管理アクセスなし",
		"de": "RAM-Benutzer kein Produkt-Administrativzugriff",
		"es": "Usuario RAM Sin Acceso Administrativo de Producto",
		"fr": "Utilisateur RAM Sans Accès Administratif au Produit",
		"pt": "Usuário RAM Sem Acesso Administrativo ao Produto"
	},
	"severity": "medium",
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
		"en": "Follow the principle of least privilege and grant only necessary permissions to RAM users.",
		"zh": "遵循最小权限原则，仅向 RAM 用户授予必要的权限。",
		"ja": "最小権限の原則に従い、RAM ユーザーに必要な権限のみを付与します。",
		"de": "Folgen Sie dem Prinzip der geringsten Berechtigung und gewähren Sie RAM-Benutzern nur notwendige Berechtigungen.",
		"es": "Siga el principio de menor privilegio y otorgue solo los permisos necesarios a los usuarios RAM.",
		"fr": "Suivez le principe du moindre privilège et accordez uniquement les permissions nécessaires aux utilisateurs RAM.",
		"pt": "Siga o princípio do menor privilégio e conceda apenas as permissões necessárias aos usuários RAM."
	},
	"resource_types": ["ALIYUN::RAM::User"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")

	# Conceptual check for attached policies
	helpers.has_property(resource, "Policies")
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
