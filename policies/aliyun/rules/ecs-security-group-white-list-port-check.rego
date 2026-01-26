package infraguard.rules.aliyun.ecs_security_group_white_list_port_check

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-white-list-port-check",
	"name": {
		"en": "Security Group Non-Whitelist Port Ingress Check",
		"zh": "安全组非白名单端口入网设置有效",
	},
	"severity": "high",
	"description": {
		"en": "Except for whitelisted ports (80), other ports should not have ingress rules allowing access from 0.0.0.0/0.",
		"zh": "除指定的白名单端口（80）外，其余端口不能有授权策略设置为允许而且来源为 0.0.0.0/0 的入方向规则，视为合规。",
	},
	"reason": {
		"en": "The security group allows access to non-whitelisted ports from all sources (0.0.0.0/0), which may expose unnecessary services to the internet.",
		"zh": "安全组允许从所有来源（0.0.0.0/0）访问非白名单端口，可能将不必要的服务暴露到互联网。",
	},
	"recommendation": {
		"en": "Only allow whitelisted ports (e.g., 80 for HTTP) to be accessible from 0.0.0.0/0. Restrict other ports to specific trusted source IP ranges.",
		"zh": "仅允许白名单端口（如 HTTP 的 80 端口）从 0.0.0.0/0 访问。将其他端口限制为特定的可信源 IP 范围。",
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
