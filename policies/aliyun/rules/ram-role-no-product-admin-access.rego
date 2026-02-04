package infraguard.rules.aliyun.ram_role_no_product_admin_access

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-role-no-product-admin-access",
	"name": {
		"en": "RAM Role No Product Admin Access",
		"zh": "RAM 角色无超级管理员或某个云产品管理员权限",
		"ja": "RAM ロールに製品管理アクセスがない",
		"de": "RAM-Rolle Kein Produkt-Admin-Zugriff",
		"es": "El Rol RAM No Tiene Acceso de Administrador de Producto",
		"fr": "Le Rôle RAM N'a Pas d'Accès Administrateur Produit",
		"pt": "A Função RAM Não Tem Acesso de Administrador de Produto",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RAM roles do not have full administrative access or product administrator permissions.",
		"zh": "确保 RAM 角色未拥有管理员权限或者某个云产品的管理员权限。",
		"ja": "RAM ロールが完全な管理アクセスまたは製品管理者権限を持っていないことを確認します。",
		"de": "Stellt sicher, dass RAM-Rollen keinen vollständigen Administratorzugriff oder Produkt-Administratorberechtigungen haben.",
		"es": "Garantiza que los roles RAM no tengan acceso administrativo completo o permisos de administrador de producto.",
		"fr": "Garantit que les rôles RAM n'ont pas d'accès administratif complet ou de permissions d'administrateur de produit.",
		"pt": "Garante que as funções RAM não tenham acesso administrativo completo ou permissões de administrador de produto.",
	},
	"reason": {
		"en": "Granting administrative access increases the risk of accidental or malicious configuration changes.",
		"zh": "授予管理权限会增加意外或恶意配置更改的风险。",
		"ja": "管理アクセスを付与すると、誤ったまたは悪意のある設定変更のリスクが増加します。",
		"de": "Die Gewährung von Administratorzugriff erhöht das Risiko versehentlicher oder böswilliger Konfigurationsänderungen.",
		"es": "Otorgar acceso administrativo aumenta el riesgo de cambios de configuración accidentales o maliciosos.",
		"fr": "Accorder un accès administratif augmente le risque de modifications de configuration accidentelles ou malveillantes.",
		"pt": "Conceder acesso administrativo aumenta o risco de alterações de configuração acidentais ou maliciosas.",
	},
	"recommendation": {
		"en": "Follow the principle of least privilege. Use product-specific read-only permissions where possible.",
		"zh": "遵循最小权限原则。尽可能使用产品特定的只读权限。",
		"ja": "最小権限の原則に従います。可能な限り製品固有の読み取り専用権限を使用します。",
		"de": "Folgen Sie dem Prinzip der geringsten Berechtigung. Verwenden Sie nach Möglichkeit produktspezifische schreibgeschützte Berechtigungen.",
		"es": "Siga el principio de privilegio mínimo. Use permisos de solo lectura específicos del producto cuando sea posible.",
		"fr": "Suivez le principe du moindre privilège. Utilisez des permissions en lecture seule spécifiques au produit lorsque c'est possible.",
		"pt": "Siga o princípio do menor privilégio. Use permissões somente leitura específicas do produto quando possível.",
	},
	"resource_types": ["ALIYUN::RAM::Role"],
}

has_admin_access(resource) if {
	doc := helpers.get_property(resource, "PolicyDocument", {})
	statements := object.get(doc, "Statement", [])
	some statement in statements
	effect := object.get(statement, "Effect", "")
	effect == "Allow"

	actions := object.get(statement, "Action", [])
	resources := object.get(statement, "Resource", "")

	is_wildcard(actions)
	is_wildcard(resources)
}

has_admin_access(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	some policy in system_policies
	is_admin_policy(policy)
}

has_admin_access_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	helpers.is_referencing(role_name_val, role_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	is_admin_policy(policy_name)
}

has_admin_access_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	helpers.is_get_att_referencing(role_name_val, role_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	is_admin_policy(policy_name)
}

has_admin_access_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	role_resource := helpers.resources_by_type("ALIYUN::RAM::Role")[role_name]
	actual_name := helpers.get_property(role_resource, "RoleName", role_name)
	role_name_val == actual_name
	policy_name := helpers.get_property(resource, "PolicyName", "")
	is_admin_policy(policy_name)
}

is_admin_policy(policy_name) if {
	policy_name == "AdministratorAccess"
}

is_admin_policy(policy_name) if {
	contains(policy_name, "Admin")
	contains(policy_name, "FullAccess")
}

is_wildcard("*") := true
is_wildcard(["*"]) := true

is_wildcard(arr) if {
	is_array(arr)
	some item in arr
	item == "*"
}

deny contains result if {
	some role_name, resource in helpers.resources_by_type("ALIYUN::RAM::Role")
	has_admin_access(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": role_name,
		"violation_path": ["Properties", "PolicyDocument"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some role_name, resource in helpers.resources_by_type("ALIYUN::RAM::Role")
	has_admin_access_via_attachment(role_name)

	result := {
		"id": rule_meta.id,
		"resource_id": role_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
