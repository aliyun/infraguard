package infraguard.rules.terraform.ram_policy_no_has_specified_document

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-policy-no-has-specified-document",
	"severity": "medium",
	"name": {
		"en": "RAM Policy No Specified Document",
		"zh": "自定义 RAM 策略不包含指定权限配置",
		"ja": "RAM ポリシーに指定されたドキュメントがない",
		"de": "RAM-Richtlinie Kein Angegebenes Dokument",
		"es": "Política RAM Sin Documento Especificado",
		"fr": "Politique RAM Sans Document Spécifié",
		"pt": "Política RAM Sem Documento Especificado"
	},
	"description": {
		"en": "Ensures custom RAM policies do not contain the specified permission configuration.",
		"zh": "确保自定义 RAM 策略未包含参数指定的授权内容。",
		"ja": "カスタム RAM ポリシーに指定された権限設定が含まれていないことを確認します。",
		"de": "Stellt sicher, dass benutzerdefinierte RAM-Richtlinien nicht die angegebene Berechtigungskonfiguration enthalten.",
		"es": "Garantiza que las políticas RAM personalizadas no contengan la configuración de permisos especificada.",
		"fr": "Garantit que les politiques RAM personnalisées ne contiennent pas la configuration de permissions spécifiée.",
		"pt": "Garante que as políticas RAM personalizadas não contenham a configuração de permissões especificada."
	},
	"reason": {
		"en": "Policies with overly broad permissions increase security risks.",
		"zh": "包含过多权限的策略会增加安全风险。",
		"ja": "過度に広範な権限を持つポリシーはセキュリティリスクを増加させます。",
		"de": "Richtlinien mit übermäßig breiten Berechtigungen erhöhen die Sicherheitsrisiken.",
		"es": "Las políticas con permisos excesivamente amplios aumentan los riesgos de seguridad.",
		"fr": "Les politiques avec des permissions trop larges augmentent les risques de sécurité.",
		"pt": "Políticas com permissões excessivamente amplas aumentam os riscos de segurança."
	},
	"recommendation": {
		"en": "Review the policy_document attribute and restrict permissions to only what is necessary. Avoid using wildcard '*' for both Action and Resource.",
		"zh": "审查 policy_document 属性并限制权限仅授予必要的权限。避免对 Action 和 Resource 同时使用通配符 '*'。",
		"ja": "policy_document 属性を確認し、必要なもののみに権限を制限します。Action と Resource の両方にワイルドカード '*' を使用しないでください。",
		"de": "Überprüfen Sie das policy_document-Attribut und beschränken Sie Berechtigungen auf das Notwendige. Vermeiden Sie die Verwendung von '*' für Action und Resource.",
		"es": "Revise el atributo policy_document y restrinja los permisos solo a lo necesario. Evite usar el comodín '*' para Action y Resource.",
		"fr": "Examinez l'attribut policy_document et restreignez les permissions à ce qui est nécessaire. Évitez d'utiliser le joker '*' pour Action et Resource.",
		"pt": "Revise o atributo policy_document e restrinja as permissões apenas ao necessário. Evite usar o curinga '*' para Action e Resource."
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

has_admin_access(doc_str) if {
	contains(doc_str, "\"Action\":\"*\"")
	contains(doc_str, "\"Resource\":\"*\"")
}

has_admin_access(doc_str) if {
	contains(doc_str, "\"Action\": \"*\"")
	contains(doc_str, "\"Resource\": \"*\"")
}

has_admin_access(doc_str) if {
	contains(doc_str, "\"Action\":[\"*\"]")
	contains(doc_str, "\"Resource\":[\"*\"]")
}

has_admin_access(doc_str) if {
	contains(doc_str, "\"Action\": [\"*\"]")
	contains(doc_str, "\"Resource\": [\"*\"]")
}
