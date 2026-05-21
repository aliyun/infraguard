package infraguard.rules.terraform.ess_scaling_configuration_sg_public_access

import rego.v1

import data.infraguard.helpers.terraform as tf

open_cidrs := {"0.0.0.0/0", "0.0.0.0", "::/0"}

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
		"en": "ESS scaling configuration security groups should not allow unrestricted public access.",
		"zh": "ESS 伸缩组配置中的安全组不包含 0.0.0.0/0，则视为合规。",
		"ja": "ESS スケーリング設定のセキュリティグループは、不正アクセスを防ぐために 0.0.0.0/0 からのアクセスを許可すべきではありません。",
		"de": "ESS-Skalierungskonfigurations-Sicherheitsgruppen sollten keinen Zugriff von 0.0.0.0/0 zulassen, um unbefugten Zugriff zu verhindern.",
		"es": "Los grupos de seguridad de configuración de escalado ESS no deben permitir el acceso desde 0.0.0.0/0 para prevenir el acceso no autorizado.",
		"fr": "Les groupes de sécurité de configuration de mise à l'échelle ESS ne doivent pas autoriser l'accès depuis 0.0.0.0/0 pour empêcher l'accès non autorisé.",
		"pt": "Os grupos de segurança de configuração de escalonamento ESS não devem permitir acesso de 0.0.0.0/0 para prevenir acesso não autorizado."
	},
	"reason": {
		"en": "The ESS scaling configuration's security group allows unrestricted public access.",
		"zh": "ESS 伸缩组配置的安全组规则中允许 0.0.0.0/0 访问，可能导致实例暴露于公网。",
		"ja": "ESS スケーリング設定のセキュリティグループが 0.0.0.0/0 からのアクセスを許可しており、インスタンスがパブリックインターネットに公開される可能性があります。",
		"de": "Die Sicherheitsgruppe der ESS-Skalierungskonfiguration erlaubt Zugriff von 0.0.0.0/0, was Instanzen dem öffentlichen Internet aussetzen kann.",
		"es": "El grupo de seguridad de la configuración de escalado ESS permite el acceso desde 0.0.0.0/0, lo que puede exponer las instancias a Internet público.",
		"fr": "Le groupe de sécurité de la configuration de mise à l'échelle ESS autorise l'accès depuis 0.0.0.0/0, ce qui peut exposer les instances à Internet public.",
		"pt": "O grupo de segurança da configuração de escalonamento ESS permite acesso de 0.0.0.0/0, o que pode expor instâncias à Internet pública."
	},
	"recommendation": {
		"en": "Restrict security group rules to specific IP ranges.",
		"zh": "将安全组规则限制为特定 IP 范围。",
		"ja": "セキュリティグループルールを 0.0.0.0/0 の代わりに特定の IP 範囲に制限します。",
		"de": "Beschränken Sie Sicherheitsgruppenregeln auf spezifische IP-Bereiche anstelle von 0.0.0.0/0.",
		"es": "Restrinja las reglas del grupo de seguridad a rangos de IP específicos en lugar de 0.0.0.0/0.",
		"fr": "Restreignez les règles du groupe de sécurité à des plages d'IP spécifiques au lieu de 0.0.0.0/0.",
		"pt": "Restrinja as regras do grupo de segurança a intervalos de IP específicos em vez de 0.0.0.0/0."
	},
	"resource_types": ["alicloud_ess_scaling_configuration", "alicloud_security_group_rule", "alicloud_security_group_rules"],
	"iac_type": "terraform"
}

configured_sg_ids(resource) := ids if {
	single_ids := {sg_id |
		sg_id := tf.get_attribute(resource, "security_group_id", "")
		not tf.is_unknown(sg_id)
		sg_id != ""
	}
	list_ids := {id |
		values := tf.get_attribute(resource, "security_group_ids", [])
		not tf.is_unknown(values)
		some id in values
		id != ""
	}
	ids := single_ids | list_ids
}

has_security_group(resource) if {
	count(configured_sg_ids(resource)) > 0
}

is_ingress(rule) if {
	lower(tf.get_attribute(rule, "type", "ingress")) == "ingress"
}

is_public_rule(rule) if {
	is_ingress(rule)
	cidr := tf.get_attribute(rule, "cidr_ip", "")
	cidr in open_cidrs
}

is_public_rule(rule) if {
	is_ingress(rule)
	cidr := tf.get_attribute(rule, "ipv6_cidr_ip", "")
	cidr in open_cidrs
}

security_group_has_public_rule(security_group_id) if {
	some _, rule in tf.resources_by_type("alicloud_security_group_rule")
	tf.get_attribute(rule, "security_group_id", "") == security_group_id
	is_public_rule(rule)
}

security_group_has_public_rule(security_group_id) if {
	some _, rules_resource in tf.resources_by_type("alicloud_security_group_rules")
	tf.get_attribute(rules_resource, "security_group_id", "") == security_group_id
	ingress_rules := tf.get_attribute(rules_resource, "ingress", [])
	is_array(ingress_rules)
	some rule in ingress_rules
	is_public_rule(rule)
}

security_group_has_public_rule(security_group_id) if {
	some _, rules_resource in tf.resources_by_type("alicloud_security_group_rules")
	tf.get_attribute(rules_resource, "security_group_id", "") == security_group_id
	ingress_rule := tf.get_attribute(rules_resource, "ingress", {})
	is_object(ingress_rule)
	is_public_rule(ingress_rule)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ess_scaling_configuration")
	not has_security_group(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ess_scaling_configuration.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ess_scaling_configuration")
	some security_group_id in configured_sg_ids(resource)
	security_group_has_public_rule(security_group_id)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ess_scaling_configuration.%s", [name]),
		"violation_path": ["security_group_ids"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
