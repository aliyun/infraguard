package infraguard.rules.terraform.ram_policy_no_statements_with_admin_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-policy-no-statements-with-admin-access-check",
	"severity": "high",
	"name": {
		"en": "RAM Policy No Admin Access",
		"zh": "禁止 RAM 策略包含管理员权限",
		"ja": "RAM ポリシーに管理者アクセスなし",
		"de": "RAM-Richtlinie kein Admin-Zugriff",
		"es": "Política RAM Sin Acceso de Administrador",
		"fr": "Politique RAM Sans Accès Administrateur",
		"pt": "Política RAM Sem Acesso de Administrador"
	},
	"description": {
		"en": "Ensures custom RAM policies do not grant full AdministratorAccess.",
		"zh": "确保自定义 RAM 策略未授予完全的管理员权限（AdministratorAccess）。",
		"ja": "カスタム RAM ポリシーが完全な AdministratorAccess を付与していないことを確認します。",
		"de": "Stellt sicher, dass benutzerdefinierte RAM-Richtlinien keinen vollständigen AdministratorAccess gewähren.",
		"es": "Garantiza que las políticas RAM personalizadas no otorguen acceso completo de administrador.",
		"fr": "Garantit que les politiques RAM personnalisées n'accordent pas un accès administrateur complet.",
		"pt": "Garante que políticas RAM personalizadas não concedam acesso completo de administrador."
	},
	"reason": {
		"en": "Granting excessive permissions increases the impact of a compromised account.",
		"zh": "授予过高权限会增加账号被盗后的危害。",
		"ja": "過剰な権限を付与すると、侵害されたアカウントの影響が増大します。",
		"de": "Das Gewähren übermäßiger Berechtigungen erhöht die Auswirkungen eines kompromittierten Kontos.",
		"es": "Otorgar permisos excesivos aumenta el impacto de una cuenta comprometida.",
		"fr": "Accorder des permissions excessives augmente l'impact d'un compte compromis.",
		"pt": "Conceder permissões excessivas aumenta o impacto de uma conta comprometida."
	},
	"recommendation": {
		"en": "Follow the principle of least privilege. Do not use '*' for both Action and Resource in the policy_document attribute.",
		"zh": "遵循最小权限原则。不要在 policy_document 属性中对 Action 和 Resource 同时使用 '*'。",
		"ja": "最小権限の原則に従います。policy_document 属性で Action と Resource の両方に '*' を使用しないでください。",
		"de": "Befolgen Sie das Prinzip der geringsten Berechtigung. Verwenden Sie nicht '*' für Action und Resource im policy_document-Attribut.",
		"es": "Siga el principio de menor privilegio. No use '*' para Action y Resource en el atributo policy_document.",
		"fr": "Suivez le principe du moindre privilège. N'utilisez pas '*' pour Action et Resource dans l'attribut policy_document.",
		"pt": "Siga o princípio do menor privilégio. Não use '*' para Action e Resource no atributo policy_document."
	},
	"resource_types": ["alicloud_ram_policy"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_policy")
	doc_str := tf.get_attribute(resource, "policy_document", "")
	doc_str != ""
	has_admin_access(doc_str)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_policy.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

is_wildcard_action(statement) if {
	statement.Action == "*"
}

is_wildcard_action(statement) if {
	is_array(statement.Action)
	some action in statement.Action
	action == "*"
}

is_wildcard_resource(statement) if {
	statement.Resource == "*"
}

is_wildcard_resource(statement) if {
	is_array(statement.Resource)
	some res in statement.Resource
	res == "*"
}

has_admin_access(doc_str) if {
	doc := json.unmarshal(doc_str)
	some statement in doc.Statement
	statement.Effect == "Allow"
	is_wildcard_action(statement)
	is_wildcard_resource(statement)
}
