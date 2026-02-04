package infraguard.rules.aliyun.ecs_instance_attached_security_group

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instance-attached-security-group",
	"name": {
		"en": "ECS Instance Attached Security Group",
		"zh": "ECS 实例绑定安全组",
		"ja": "ECS インスタンスにセキュリティグループがアタッチされている",
		"de": "ECS-Instanz Sicherheitsgruppe angehängt",
		"es": "Instancia ECS con Grupo de Seguridad Adjunto",
		"fr": "Instance ECS avec Groupe de Sécurité Attaché",
		"pt": "Instância ECS com Grupo de Segurança Anexado",
	},
	"severity": "high",
	"description": {
		"en": "If the ECS instance is included in the specified security group, the configuration is considered compliant.",
		"zh": "如果 ECS 实例已关联指定的安全组，则视为合规。",
		"ja": "ECS インスタンスが指定されたセキュリティグループに含まれている場合、設定は準拠していると見なされます。",
		"de": "Wenn die ECS-Instanz in der angegebenen Sicherheitsgruppe enthalten ist, wird die Konfiguration als konform betrachtet.",
		"es": "Si la instancia ECS está incluida en el grupo de seguridad especificado, la configuración se considera conforme.",
		"fr": "Si l'instance ECS est incluse dans le groupe de sécurité spécifié, la configuration est considérée comme conforme.",
		"pt": "Se a instância ECS estiver incluída no grupo de segurança especificado, a configuração é considerada conforme.",
	},
	"reason": {
		"en": "The ECS instance is not attached to any security group, which may leave it without proper network access control.",
		"zh": "ECS 实例未关联任何安全组，可能导致缺乏适当的网络访问控制。",
		"ja": "ECS インスタンスがセキュリティグループにアタッチされていないため、適切なネットワークアクセス制御が欠如している可能性があります。",
		"de": "Die ECS-Instanz ist keiner Sicherheitsgruppe angehängt, was zu fehlender ordnungsgemäßer Netzwerkzugriffskontrolle führen kann.",
		"es": "La instancia ECS no está adjunta a ningún grupo de seguridad, lo que puede dejarla sin control adecuado de acceso a la red.",
		"fr": "L'instance ECS n'est attachée à aucun groupe de sécurité, ce qui peut la laisser sans contrôle d'accès réseau approprié.",
		"pt": "A instância ECS não está anexada a nenhum grupo de segurança, o que pode deixá-la sem controle adequado de acesso à rede.",
	},
	"recommendation": {
		"en": "Attach the ECS instance to at least one security group by setting SecurityGroupId or SecurityGroupIds property.",
		"zh": "通过设置 SecurityGroupId 或 SecurityGroupIds 属性，将 ECS 实例关联至少一个安全组。",
		"ja": "SecurityGroupId または SecurityGroupIds プロパティを設定して、ECS インスタンスを少なくとも1つのセキュリティグループにアタッチします。",
		"de": "Hängen Sie die ECS-Instanz an mindestens eine Sicherheitsgruppe an, indem Sie die Eigenschaft SecurityGroupId oder SecurityGroupIds setzen.",
		"es": "Adjunte la instancia ECS a al menos un grupo de seguridad estableciendo la propiedad SecurityGroupId o SecurityGroupIds.",
		"fr": "Attachez l'instance ECS à au moins un groupe de sécurité en définissant la propriété SecurityGroupId ou SecurityGroupIds.",
		"pt": "Anexe a instância ECS a pelo menos um grupo de segurança definindo a propriedade SecurityGroupId ou SecurityGroupIds.",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

# Check if the instance has SecurityGroupId set
has_security_group_id(resource) if {
	helpers.has_property(resource, "SecurityGroupId")
	resource.Properties.SecurityGroupId != ""
}

# Check if the instance has SecurityGroupIds set with at least one entry
has_security_group_ids(resource) if {
	helpers.has_property(resource, "SecurityGroupIds")
	count(resource.Properties.SecurityGroupIds) > 0
}

# Instance is attached to security group if either property is set
is_attached_to_security_group(resource) if {
	has_security_group_id(resource)
}

is_attached_to_security_group(resource) if {
	has_security_group_ids(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_types({"ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"})
	not is_attached_to_security_group(resource)
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
