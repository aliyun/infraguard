package infraguard.rules.aliyun.ess_scaling_configuration_sg_public_access

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ess-scaling-configuration-sg-public-access",
	"severity": "high",
	"name": {
		"en": "ESS Scaling Configuration Security Group Public Access",
		"zh": "ESS 伸缩组配置的安全组不应设置为 0.0.0.0/0",
		"ja": "ESS スケーリング設定セキュリティグループパブリックアクセス",
		"de": "ESS-Skalierungskonfiguration Sicherheitsgruppe Öffentlicher Zugriff",
		"es": "Acceso Público del Grupo de Seguridad de Configuración de Escalado ESS",
		"fr": "Accès Public du Groupe de Sécurité de Configuration de Mise à l'Échelle ESS",
		"pt": "Acesso Público do Grupo de Segurança de Configuração de Escalonamento ESS"
	},
	"description": {
		"en": "ESS scaling configuration security groups should not allow access from 0.0.0.0/0 to prevent unauthorized access.",
		"zh": "ESS 伸缩组配置中的安全组不包含 0.0.0.0/0，则视为合规。",
		"ja": "ESS スケーリング設定のセキュリティグループは、不正アクセスを防ぐために 0.0.0.0/0 からのアクセスを許可すべきではありません。",
		"de": "ESS-Skalierungskonfigurations-Sicherheitsgruppen sollten keinen Zugriff von 0.0.0.0/0 zulassen, um unbefugten Zugriff zu verhindern.",
		"es": "Los grupos de seguridad de configuración de escalado ESS no deben permitir el acceso desde 0.0.0.0/0 para prevenir el acceso no autorizado.",
		"fr": "Les groupes de sécurité de configuration de mise à l'échelle ESS ne doivent pas autoriser l'accès depuis 0.0.0.0/0 pour empêcher l'accès non autorisé.",
		"pt": "Os grupos de segurança de configuração de escalonamento ESS não devem permitir acesso de 0.0.0.0/0 para prevenir acesso não autorizado."
	},
	"reason": {
		"en": "The ESS scaling configuration's security group allows access from 0.0.0.0/0, which may expose instances to the public internet.",
		"zh": "ESS 伸缩组配置的安全组规则中允许 0.0.0.0/0 访问，可能导致实例暴露于公网。",
		"ja": "ESS スケーリング設定のセキュリティグループが 0.0.0.0/0 からのアクセスを許可しており、インスタンスがパブリックインターネットに公開される可能性があります。",
		"de": "Die Sicherheitsgruppe der ESS-Skalierungskonfiguration erlaubt Zugriff von 0.0.0.0/0, was Instanzen dem öffentlichen Internet aussetzen kann.",
		"es": "El grupo de seguridad de la configuración de escalado ESS permite el acceso desde 0.0.0.0/0, lo que puede exponer las instancias a Internet público.",
		"fr": "Le groupe de sécurité de la configuration de mise à l'échelle ESS autorise l'accès depuis 0.0.0.0/0, ce qui peut exposer les instances à Internet public.",
		"pt": "O grupo de segurança da configuração de escalonamento ESS permite acesso de 0.0.0.0/0, o que pode expor instâncias à Internet pública."
	},
	"recommendation": {
		"en": "Restrict security group rules to specific IP ranges instead of 0.0.0.0/0.",
		"zh": "将安全组规则限制为特定 IP 范围，避免使用 0.0.0.0/0。",
		"ja": "セキュリティグループルールを 0.0.0.0/0 の代わりに特定の IP 範囲に制限します。",
		"de": "Beschränken Sie Sicherheitsgruppenregeln auf spezifische IP-Bereiche anstelle von 0.0.0.0/0.",
		"es": "Restrinja las reglas del grupo de seguridad a rangos de IP específicos en lugar de 0.0.0.0/0.",
		"fr": "Restreignez les règles du groupe de sécurité à des plages d'IP spécifiques au lieu de 0.0.0.0/0.",
		"pt": "Restrinja as regras do grupo de segurança a intervalos de IP específicos em vez de 0.0.0.0/0."
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"]
}

has_security_group(resource) if {
	security_group_id := helpers.get_property(resource, "SecurityGroupId", "")
	security_group_id != ""
}

has_security_group(resource) if {
	security_group_ids := helpers.get_property(resource, "SecurityGroupIds", [])
	count(security_group_ids) > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not has_security_group(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": "The scaling configuration does not have explicit security groups configured.",
			"recommendation": "Configure specific security groups for the scaling configuration.",
		},
	}
}
