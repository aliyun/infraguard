package infraguard.rules.aliyun.ecs_security_group_white_list_port_check

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-white-list-port-check",
	"name": {
		"en": "Security Group Non-Whitelist Port Ingress Check",
		"zh": "安全组非白名单端口入网设置有效",
		"ja": "セキュリティグループの非ホワイトリストポートイングレスチェック",
		"de": "Sicherheitsgruppe Nicht-Whitelist-Port-Ingress-Prüfung",
		"es": "Verificación de Ingress de Puerto No en Lista Blanca de Grupo de Seguridad",
		"fr": "Vérification d'Ingress de Port Non-Liste Blanche du Groupe de Sécurité",
		"pt": "Verificação de Ingresso de Porta Não na Lista Branca do Grupo de Segurança",
	},
	"severity": "high",
	"description": {
		"en": "Except for whitelisted ports (80), other ports should not have ingress rules allowing access from 0.0.0.0/0.",
		"zh": "除指定的白名单端口（80）外，其余端口不能有授权策略设置为允许而且来源为 0.0.0.0/0 的入方向规则，视为合规。",
		"ja": "ホワイトリストポート（80）を除いて、他のポートは 0.0.0.0/0 からのアクセスを許可するイングレスルールを持つべきではありません。",
		"de": "Außer Whitelist-Ports (80) sollten andere Ports keine Ingress-Regeln haben, die Zugriff von 0.0.0.0/0 erlauben.",
		"es": "Excepto los puertos en lista blanca (80), otros puertos no deben tener reglas de ingreso que permitan el acceso desde 0.0.0.0/0.",
		"fr": "À l'exception des ports en liste blanche (80), les autres ports ne doivent pas avoir de règles d'ingress autorisant l'accès depuis 0.0.0.0/0.",
		"pt": "Exceto portas na lista branca (80), outras portas não devem ter regras de ingresso que permitam acesso de 0.0.0.0/0.",
	},
	"reason": {
		"en": "The security group allows access to non-whitelisted ports from all sources (0.0.0.0/0), which may expose unnecessary services to the internet.",
		"zh": "安全组允许从所有来源（0.0.0.0/0）访问非白名单端口，可能将不必要的服务暴露到互联网。",
		"ja": "セキュリティグループがすべてのソース（0.0.0.0/0）からの非ホワイトリストポートへのアクセスを許可しているため、不要なサービスがインターネットに公開される可能性があります。",
		"de": "Die Sicherheitsgruppe erlaubt Zugriff auf Nicht-Whitelist-Ports von allen Quellen (0.0.0.0/0), was unnötige Dienste dem Internet aussetzen kann.",
		"es": "El grupo de seguridad permite el acceso a puertos no incluidos en la lista blanca desde todas las fuentes (0.0.0.0/0), lo que puede exponer servicios innecesarios a internet.",
		"fr": "Le groupe de sécurité autorise l'accès aux ports non listés en liste blanche depuis toutes les sources (0.0.0.0/0), ce qui peut exposer des services inutiles à Internet.",
		"pt": "O grupo de segurança permite acesso a portas não na lista branca de todas as fontes (0.0.0.0/0), o que pode expor serviços desnecessários à internet.",
	},
	"recommendation": {
		"en": "Only allow whitelisted ports (e.g., 80 for HTTP) to be accessible from 0.0.0.0/0. Restrict other ports to specific trusted source IP ranges.",
		"zh": "仅允许白名单端口（如 HTTP 的 80 端口）从 0.0.0.0/0 访问。将其他端口限制为特定的可信源 IP 范围。",
		"ja": "ホワイトリストポート（例：HTTP の 80 ポート）のみが 0.0.0.0/0 からアクセス可能になるようにします。他のポートは特定の信頼できるソース IP 範囲に制限します。",
		"de": "Erlauben Sie nur Whitelist-Ports (z. B. 80 für HTTP), die von 0.0.0.0/0 zugänglich sind. Beschränken Sie andere Ports auf spezifische vertrauenswürdige Quell-IP-Bereiche.",
		"es": "Solo permita que los puertos en lista blanca (por ejemplo, 80 para HTTP) sean accesibles desde 0.0.0.0/0. Restrinja otros puertos a rangos de IP de origen confiables específicos.",
		"fr": "Autorisez uniquement les ports en liste blanche (par exemple, 80 pour HTTP) à être accessibles depuis 0.0.0.0/0. Restreignez les autres ports à des plages d'IP source de confiance spécifiques.",
		"pt": "Permita apenas portas na lista branca (por exemplo, 80 para HTTP) sejam acessíveis de 0.0.0.0/0. Restrinja outras portas a intervalos de IP de origem confiáveis específicos.",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupIngress", "ALIYUN::ECS::SecurityGroupIngresses"],
}

# Whitelisted ports that are allowed from 0.0.0.0/0
whitelist_ports := [80]

# Check if a port range contains only whitelisted ports
is_only_whitelist_ports(port_range) if {
	[start, end] := helpers.parse_port_range(port_range)
	start == end
	some port in whitelist_ports
	start == port
}

# Check if a rule allows non-whitelisted ports from public sources
is_non_whitelist_public_rule(rule) if {
	# Source is 0.0.0.0/0 (all IPv4)
	rule.SourceCidrIp == "0.0.0.0/0"

	# Policy is accept (default)
	object.get(rule, "Policy", "accept") == "accept"

	# Not all ports (-1/-1 is handled by other rules)
	rule.PortRange != "-1/-1"

	# Port range is not only whitelisted ports
	not is_only_whitelist_ports(rule.PortRange)
}

is_non_whitelist_public_rule(rule) if {
	# Source is ::/0 (all IPv6)
	rule.Ipv6SourceCidrIp == "::/0"

	# Policy is accept (default)
	object.get(rule, "Policy", "accept") == "accept"

	# Not all ports (-1/-1 is handled by other rules)
	rule.PortRange != "-1/-1"

	# Port range is not only whitelisted ports
	not is_only_whitelist_ports(rule.PortRange)
}

# Check SecurityGroup resource for ingress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupIngress
	is_non_whitelist_public_rule(rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIngress", format_int(i, 10)],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

# Check SecurityGroupIngress resource
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroupIngress")
	props := resource.Properties
	ingress_rule := {
		"PortRange": props.PortRange,
		"SourceCidrIp": object.get(props, "SourceCidrIp", ""),
		"Ipv6SourceCidrIp": object.get(props, "Ipv6SourceCidrIp", ""),
		"Policy": object.get(props, "Policy", "accept"),
	}
	is_non_whitelist_public_rule(ingress_rule)
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

# Check SecurityGroupIngresses resource
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroupIngresses")
	some i, perm in resource.Properties.Permissions
	ingress_rule := {
		"PortRange": perm.PortRange,
		"SourceCidrIp": object.get(perm, "SourceCidrIp", ""),
		"Ipv6SourceCidrIp": object.get(perm, "Ipv6SourceCidrIp", ""),
		"Policy": object.get(perm, "Policy", "accept"),
	}
	is_non_whitelist_public_rule(ingress_rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Permissions", format_int(i, 10)],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
