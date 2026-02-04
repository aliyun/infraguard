package infraguard.rules.aliyun.ess_scaling_configuration_attach_security_group

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-scaling-configuration-attach-security-group",
	"name": {
		"en": "ESS Scaling Configuration Security Group",
		"zh": "弹性伸缩配置中为实例设置关联安全组",
		"ja": "ESS スケーリング設定セキュリティグループ",
		"de": "ESS-Skalierungskonfiguration Sicherheitsgruppe",
		"es": "Grupo de Seguridad de Configuración de Escalado ESS",
		"fr": "Groupe de Sécurité de Configuration de Mise à l'Échelle ESS",
		"pt": "Grupo de Segurança de Configuração de Escalonamento ESS",
	},
	"severity": "medium",
	"description": {
		"en": "ESS scaling configurations should attach security groups to instances for proper network isolation and access control.",
		"zh": "弹性伸缩配置中设置了实例要加入的安全组，视为合规。",
		"ja": "ESS スケーリング設定は、適切なネットワーク分離とアクセス制御のためにインスタンスにセキュリティグループをアタッチする必要があります。",
		"de": "ESS-Skalierungskonfigurationen sollten Sicherheitsgruppen an Instanzen anhängen, um ordnungsgemäße Netzwerkisolation und Zugriffskontrolle zu gewährleisten.",
		"es": "Las configuraciones de escalado ESS deben adjuntar grupos de seguridad a las instancias para un aislamiento de red y control de acceso adecuados.",
		"fr": "Les configurations de mise à l'échelle ESS doivent attacher des groupes de sécurité aux instances pour une isolation réseau et un contrôle d'accès appropriés.",
		"pt": "As configurações de escalonamento ESS devem anexar grupos de segurança às instâncias para isolamento de rede e controle de acesso adequados.",
	},
	"reason": {
		"en": "The ESS scaling configuration does not have security groups attached, which may result in instances without proper network access control.",
		"zh": "弹性伸缩配置未关联安全组，实例可能缺少网络访问控制。",
		"ja": "ESS スケーリング設定にセキュリティグループがアタッチされていないため、適切なネットワークアクセス制御がないインスタンスが発生する可能性があります。",
		"de": "Die ESS-Skalierungskonfiguration hat keine angehängten Sicherheitsgruppen, was zu Instanzen ohne ordnungsgemäße Netzwerkzugriffskontrolle führen kann.",
		"es": "La configuración de escalado ESS no tiene grupos de seguridad adjuntos, lo que puede resultar en instancias sin control de acceso de red adecuado.",
		"fr": "La configuration de mise à l'échelle ESS n'a pas de groupes de sécurité attachés, ce qui peut entraîner des instances sans contrôle d'accès réseau approprié.",
		"pt": "A configuração de escalonamento ESS não tem grupos de segurança anexados, o que pode resultar em instâncias sem controle de acesso de rede adequado.",
	},
	"recommendation": {
		"en": "Add security groups to the scaling configuration using SecurityGroupId or SecurityGroupIds properties.",
		"zh": "在伸缩配置中使用 SecurityGroupId 或 SecurityGroupIds 属性添加安全组。",
		"ja": "SecurityGroupId または SecurityGroupIds プロパティを使用して、スケーリング設定にセキュリティグループを追加します。",
		"de": "Fügen Sie Sicherheitsgruppen zur Skalierungskonfiguration hinzu, indem Sie die Eigenschaften SecurityGroupId oder SecurityGroupIds verwenden.",
		"es": "Agregue grupos de seguridad a la configuración de escalado usando las propiedades SecurityGroupId o SecurityGroupIds.",
		"fr": "Ajoutez des groupes de sécurité à la configuration de mise à l'échelle en utilisant les propriétés SecurityGroupId ou SecurityGroupIds.",
		"pt": "Adicione grupos de segurança à configuração de escalonamento usando as propriedades SecurityGroupId ou SecurityGroupIds.",
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"],
}

# Check if scaling configuration has security groups attached
has_security_group(resource) if {
	security_group_id := helpers.get_property(resource, "SecurityGroupId", "")
	security_group_id != ""
}

has_security_group(resource) if {
	security_group_ids := helpers.get_property(resource, "SecurityGroupIds", [])
	count(security_group_ids) > 0
}

# Deny rule: ESS scaling configurations must have security groups attached
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not has_security_group(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
