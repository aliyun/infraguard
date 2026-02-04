package infraguard.rules.aliyun.ram_policy_no_has_specified_document

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ram-policy-no-has-specified-document",
	"name": {
		"en": "RAM Policy No Specified Document",
		"zh": "自定义 RAM 策略不包含指定权限配置",
		"ja": "RAM ポリシーに指定されたドキュメントがない",
		"de": "RAM-Richtlinie Kein Angegebenes Dokument",
		"es": "Política RAM Sin Documento Especificado",
		"fr": "Politique RAM Sans Document Spécifié",
		"pt": "Política RAM Sem Documento Especificado",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures custom RAM policies do not contain the specified permission configuration.",
		"zh": "确保自定义 RAM 策略未包含参数指定的授权内容。",
		"ja": "カスタム RAM ポリシーに指定された権限設定が含まれていないことを確認します。",
		"de": "Stellt sicher, dass benutzerdefinierte RAM-Richtlinien nicht die angegebene Berechtigungskonfiguration enthalten.",
		"es": "Garantiza que las políticas RAM personalizadas no contengan la configuración de permisos especificada.",
		"fr": "Garantit que les politiques RAM personnalisées ne contiennent pas la configuration de permissions spécifiée.",
		"pt": "Garante que as políticas RAM personalizadas não contenham a configuração de permissões especificada.",
	},
	"reason": {
		"en": "Policies with overly broad permissions increase security risks.",
		"zh": "包含过多权限的策略会增加安全风险。",
		"ja": "過度に広範な権限を持つポリシーはセキュリティリスクを増加させます。",
		"de": "Richtlinien mit übermäßig breiten Berechtigungen erhöhen die Sicherheitsrisiken.",
		"es": "Las políticas con permisos excesivamente amplios aumentan los riesgos de seguridad.",
		"fr": "Les politiques avec des permissions trop larges augmentent les risques de sécurité.",
		"pt": "Políticas com permissões excessivamente amplas aumentam os riscos de segurança.",
	},
	"recommendation": {
		"en": "Review and restrict the policy permissions to only what's necessary.",
		"zh": "审查并限制策略权限，仅授予必要的权限。",
		"ja": "ポリシーの権限を確認し、必要なもののみに制限します。",
		"de": "Überprüfen und beschränken Sie die Richtlinienberechtigungen auf das Notwendige.",
		"es": "Revise y restrinja los permisos de la política solo a lo necesario.",
		"fr": "Examinez et restreignez les permissions de la politique à ce qui est nécessaire uniquement.",
		"pt": "Revise e restrinja as permissões da política apenas ao necessário.",
	},
	"resource_types": ["ALIYUN::RAM::ManagedPolicy"],
}

get_statements(resource) := statements if {
	doc := helpers.get_property(resource, "PolicyDocument", {})
	statements := object.get(doc, "Statement", [])
}

matches_specified_config(statement, specified_actions, specified_resources) if {
	actions := object.get(statement, "Action", [])
	some action in actions
	some specified in specified_actions
	action == specified
}

matches_specified_config(statement, specified_actions, specified_resources) if {
	resources := object.get(statement, "Resource", [])
	some resource in resources
	some specified in specified_resources
	resource == specified
}

deny contains result if {
	some policy_name, resource in helpers.resources_by_type("ALIYUN::RAM::ManagedPolicy")
	statements := get_statements(resource)

	some statement in statements
	effect := object.get(statement, "Effect", "")
	effect == "Allow"

	is_admin_access(statement)

	result := {
		"id": rule_meta.id,
		"resource_id": policy_name,
		"violation_path": ["Properties", "PolicyDocument", "Statement"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

is_admin_access(statement) if {
	actions := object.get(statement, "Action", [])
	resources := object.get(statement, "Resource", "")
	actions == ["*"]
	resources == ["*"]
}

is_admin_access(statement) if {
	actions := object.get(statement, "Action", "")
	resources := object.get(statement, "Resource", "")
	actions == "*"
	resources == "*"
}

is_admin_access(statement) if {
	actions := object.get(statement, "Action", [])
	resources := object.get(statement, "Resource", [])
	"*" in actions
	"*" in resources
}
