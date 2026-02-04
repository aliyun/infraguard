package infraguard.rules.aliyun.ecs_security_group_type_not_normal

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-type-not-normal",
	"name": {
		"en": "Use Enterprise Security Group Type",
		"zh": "使用企业类型安全组",
		"ja": "エンタープライズセキュリティグループタイプを使用",
		"de": "Unternehmens-Sicherheitsgruppentyp verwenden",
		"es": "Usar Tipo de Grupo de Seguridad Empresarial",
		"fr": "Utiliser le Type de Groupe de Sécurité Entreprise",
		"pt": "Usar Tipo de Grupo de Segurança Empresarial",
	},
	"severity": "low",
	"description": {
		"en": "ECS security group type should not be normal type. Using enterprise security group is considered compliant.",
		"zh": "ECS 安全组类型非普通安全组，视为合规。",
		"ja": "ECS セキュリティグループタイプは通常タイプであってはなりません。エンタープライズセキュリティグループの使用は準拠と見なされます。",
		"de": "Der ECS-Sicherheitsgruppentyp sollte nicht der normale Typ sein. Die Verwendung von Unternehmens-Sicherheitsgruppen gilt als konform.",
		"es": "El tipo de grupo de seguridad ECS no debe ser tipo normal. Usar grupo de seguridad empresarial se considera conforme.",
		"fr": "Le type de groupe de sécurité ECS ne doit pas être de type normal. L'utilisation d'un groupe de sécurité entreprise est considérée comme conforme.",
		"pt": "O tipo de grupo de segurança ECS não deve ser tipo normal. Usar grupo de segurança empresarial é considerado conforme.",
	},
	"reason": {
		"en": "The security group is using normal type instead of enterprise type, which may have limitations in functionality and performance.",
		"zh": "安全组使用了普通类型而非企业类型，可能在功能和性能上存在限制。",
		"ja": "セキュリティグループがエンタープライズタイプではなく通常タイプを使用しているため、機能とパフォーマンスに制限がある可能性があります。",
		"de": "Die Sicherheitsgruppe verwendet den normalen Typ anstelle des Unternehmenstyps, was Einschränkungen bei Funktionalität und Leistung haben kann.",
		"es": "El grupo de seguridad está usando tipo normal en lugar de tipo empresarial, lo que puede tener limitaciones en funcionalidad y rendimiento.",
		"fr": "Le groupe de sécurité utilise le type normal au lieu du type entreprise, ce qui peut avoir des limitations en termes de fonctionnalité et de performances.",
		"pt": "O grupo de segurança está usando tipo normal em vez de tipo empresarial, o que pode ter limitações em funcionalidade e desempenho.",
	},
	"recommendation": {
		"en": "Set SecurityGroupType property to 'enterprise' to use enterprise security group which provides better performance and more features.",
		"zh": "将 SecurityGroupType 属性设置为'enterprise'以使用企业安全组，获得更好的性能和更多功能。",
		"ja": "SecurityGroupType プロパティを 'enterprise' に設定して、より優れたパフォーマンスとより多くの機能を提供するエンタープライズセキュリティグループを使用します。",
		"de": "Setzen Sie die Eigenschaft SecurityGroupType auf 'enterprise', um Unternehmens-Sicherheitsgruppen zu verwenden, die bessere Leistung und mehr Funktionen bieten.",
		"es": "Establezca la propiedad SecurityGroupType en 'enterprise' para usar grupo de seguridad empresarial que proporciona mejor rendimiento y más funciones.",
		"fr": "Définissez la propriété SecurityGroupType sur 'enterprise' pour utiliser un groupe de sécurité entreprise qui offre de meilleures performances et plus de fonctionnalités.",
		"pt": "Defina a propriedade SecurityGroupType como 'enterprise' para usar grupo de segurança empresarial que oferece melhor desempenho e mais recursos.",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup"],
}

# Check if security group uses enterprise type
is_enterprise_type(resource) if {
	resource.Properties.SecurityGroupType == "enterprise"
}

# Generate deny for non-compliant resources (normal type or not specified)
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	not is_enterprise_type(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
