package infraguard.rules.aliyun.ecs_security_group_description_check

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-description-check",
	"name": {
		"en": "Security Group Description Not Empty",
		"zh": "安全组描述信息不能为空",
		"ja": "セキュリティグループの説明が空でない",
		"de": "Sicherheitsgruppe Beschreibung nicht leer",
		"es": "Descripción de Grupo de Seguridad No Vacía",
		"fr": "Description du Groupe de Sécurité Non Vide",
		"pt": "Descrição de Grupo de Segurança Não Vazia",
	},
	"severity": "low",
	"description": {
		"en": "Security group description should not be empty. Having a description helps with management and auditing.",
		"zh": "安全组描述信息不为空，视为合规。",
		"ja": "セキュリティグループの説明は空であってはなりません。説明があると、管理と監査に役立ちます。",
		"de": "Die Beschreibung der Sicherheitsgruppe sollte nicht leer sein. Eine Beschreibung hilft bei der Verwaltung und Prüfung.",
		"es": "La descripción del grupo de seguridad no debe estar vacía. Tener una descripción ayuda con la gestión y la auditoría.",
		"fr": "La description du groupe de sécurité ne doit pas être vide. Avoir une description aide à la gestion et à l'audit.",
		"pt": "A descrição do grupo de segurança não deve estar vazia. Ter uma descrição ajuda com gerenciamento e auditoria.",
	},
	"reason": {
		"en": "The security group does not have a description, which makes it difficult to understand its purpose and manage it effectively.",
		"zh": "安全组没有描述信息，难以理解其用途并进行有效管理。",
		"ja": "セキュリティグループに説明がないため、その目的を理解し、効果的に管理することが困難です。",
		"de": "Die Sicherheitsgruppe hat keine Beschreibung, was es schwierig macht, ihren Zweck zu verstehen und sie effektiv zu verwalten.",
		"es": "El grupo de seguridad no tiene descripción, lo que dificulta entender su propósito y gestionarlo eficazmente.",
		"fr": "Le groupe de sécurité n'a pas de description, ce qui rend difficile de comprendre son objectif et de le gérer efficacement.",
		"pt": "O grupo de segurança não tem descrição, o que dificulta entender seu propósito e gerenciá-lo efetivamente.",
	},
	"recommendation": {
		"en": "Add a meaningful description to the security group using the Description property to explain its purpose and usage.",
		"zh": "使用 Description 属性为安全组添加有意义的描述，说明其用途和使用场景。",
		"ja": "Description プロパティを使用して、セキュリティグループに目的と使用方法を説明する意味のある説明を追加します。",
		"de": "Fügen Sie der Sicherheitsgruppe eine aussagekräftige Beschreibung hinzu, indem Sie die Eigenschaft Description verwenden, um ihren Zweck und ihre Verwendung zu erklären.",
		"es": "Agregue una descripción significativa al grupo de seguridad usando la propiedad Description para explicar su propósito y uso.",
		"fr": "Ajoutez une description significative au groupe de sécurité en utilisant la propriété Description pour expliquer son objectif et son utilisation.",
		"pt": "Adicione uma descrição significativa ao grupo de segurança usando a propriedade Description para explicar seu propósito e uso.",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup"],
}

# Check if security group has a non-empty description
has_description(resource) if {
	helpers.has_property(resource, "Description")
	resource.Properties.Description != ""
}

# Generate deny for non-compliant resources
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	not has_description(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Description"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
