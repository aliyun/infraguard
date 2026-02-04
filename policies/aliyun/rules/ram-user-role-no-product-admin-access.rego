package infraguard.rules.aliyun.ram_user_role_no_product_admin_access

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-user-role-no-product-admin-access",
	"name": {
		"en": "RAM User Role No Product Admin Access",
		"zh": "ram 用户定义的角色不包括产品管理权限",
		"ja": "RAM ユーザーロールに製品管理アクセスがない",
		"de": "RAM-Benutzerrolle Kein Produkt-Admin-Zugriff",
		"es": "El Rol de Usuario RAM No Tiene Acceso de Administrador de Producto",
		"fr": "Le Rôle d'Utilisateur RAM N'a Pas d'Accès Administrateur Produit",
		"pt": "A Função de Usuário RAM Não Tem Acesso de Administrador de Produto",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures RAM user-defined roles do not have product administrative permissions.",
		"zh": "确保 RAM 用户创建的角色未拥有管理员权限或者某个云产品的管理员权限。",
		"ja": "RAM ユーザー定義のロールが製品管理権限を持っていないことを確認します。",
		"de": "Stellt sicher, dass RAM-benutzerdefinierte Rollen keine Produkt-Administratorberechtigungen haben.",
		"es": "Garantiza que los roles definidos por el usuario RAM no tengan permisos administrativos de producto.",
		"fr": "Garantit que les rôles définis par l'utilisateur RAM n'ont pas de permissions administratives de produit.",
		"pt": "Garante que as funções definidas pelo usuário RAM não tenham permissões administrativas de produto.",
	},
	"reason": {
		"en": "Custom roles with admin permissions increase security risks.",
		"zh": "具有管理权限的自定义角色会增加安全风险。",
		"ja": "管理権限を持つカスタムロールはセキュリティリスクを増加させます。",
		"de": "Benutzerdefinierte Rollen mit Admin-Berechtigungen erhöhen die Sicherheitsrisiken.",
		"es": "Los roles personalizados con permisos de administrador aumentan los riesgos de seguridad.",
		"fr": "Les rôles personnalisés avec des permissions d'administrateur augmentent les risques de sécurité.",
		"pt": "Funções personalizadas com permissões de administrador aumentam os riscos de segurança.",
	},
	"recommendation": {
		"en": "Review role permissions and remove excessive privileges.",
		"zh": "审查角色权限并移除过多的权限。",
		"ja": "ロール権限を確認し、過剰な権限を削除します。",
		"de": "Überprüfen Sie Rollenberechtigungen und entfernen Sie übermäßige Berechtigungen.",
		"es": "Revise los permisos del rol y elimine los privilegios excesivos.",
		"fr": "Examinez les permissions du rôle et supprimez les privilèges excessifs.",
		"pt": "Revise as permissões da função e remova privilégios excessivos.",
	},
	"resource_types": ["ALIYUN::RAM::Role"],
}

is_service_linked_role(policy_doc) if {
	statements := object.get(policy_doc, "Statement", [])
	some statement in statements
	effect := object.get(statement, "Effect", "")
	effect == "Allow"

	principal := object.get(statement, "Principal", {})
	services := object.get(principal, "Service", [])

	some service in services
	contains(service, ".aliyuncs.com")
}

has_admin_access(resource) if {
	policies := helpers.get_property(resource, "Policies", [])
	some policy_def in policies
	doc := object.get(policy_def, "PolicyDocument", {})

	statements := object.get(doc, "Statement", [])
	some statement in statements
	effect := object.get(statement, "Effect", "")
	effect == "Allow"

	actions := object.get(statement, "Action", [])
	resources := object.get(statement, "Resource", [])

	is_wildcard(actions)
	is_wildcard(resources)
}

has_admin_access(resource) if {
	policy_attachments := helpers.get_property(resource, "PolicyAttachments", {})
	system_policies := object.get(policy_attachments, "System", [])
	some policy in system_policies
	policy == "AdministratorAccess"
}

has_admin_access_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	helpers.is_referencing(role_name_val, role_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name == "AdministratorAccess"
}

has_admin_access_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	helpers.is_get_att_referencing(role_name_val, role_name)
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name == "AdministratorAccess"
}

has_admin_access_via_attachment(role_name) if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AttachPolicyToRole")
	role_name_val := helpers.get_property(resource, "RoleName", "")
	role_resource := helpers.resources_by_type("ALIYUN::RAM::Role")[role_name]
	actual_name := helpers.get_property(role_resource, "RoleName", role_name)
	role_name_val == actual_name
	policy_name := helpers.get_property(resource, "PolicyName", "")
	policy_name == "AdministratorAccess"
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

	policy_doc := helpers.get_property(resource, "AssumeRolePolicyDocument", {})
	not is_service_linked_role(policy_doc)

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

	policy_doc := helpers.get_property(resource, "AssumeRolePolicyDocument", {})
	not is_service_linked_role(policy_doc)

	has_admin_access_via_attachment(role_name)

	result := {
		"id": rule_meta.id,
		"resource_id": role_name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
