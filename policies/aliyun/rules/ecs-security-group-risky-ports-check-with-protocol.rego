package infraguard.rules.aliyun.ecs_security_group_risky_ports_check_with_protocol

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-risky-ports-check-with-protocol",
	"name": {
		"en": "Security Group Risky Ports Check with Protocol",
		"zh": "安全组指定协议不允许对全部网段开启风险端口",
	},
	"severity": "high",
	"description": {
		"en": "When security group ingress source is set to 0.0.0.0/0, the port range should not include risky ports (22, 3389) for specified protocols (TCP/UDP), to reduce the risk of brute force attacks.",
		"zh": "当安全组入网网段设置为 0.0.0.0/0 时，指定协议的端口范围不包含指定风险端口，降低服务器登录密码被暴力破解风险，视为合规。默认检测风险端口为 22、3389。",
	},
	"reason": {
		"en": "The security group allows access to risky ports (SSH:22, RDP:3389) from all sources (0.0.0.0/0), which increases the risk of brute force password attacks.",
		"zh": "安全组允许从所有来源（0.0.0.0/0）访问风险端口（SSH:22、RDP:3389），增加了暴力破解密码的风险。",
	},
	"recommendation": {
		"en": "Restrict access to ports 22 (SSH) and 3389 (RDP) by limiting the source CIDR to specific trusted IP ranges instead of 0.0.0.0/0.",
		"zh": "限制对端口 22（SSH）和 3389（RDP）的访问，将来源 CIDR 限制为特定的可信 IP 范围，而不是 0.0.0.0/0。",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupIngress", "ALIYUN::ECS::SecurityGroupIngresses"],
}

# Risky ports that should not be exposed to all sources
risky_ports := [22, 3389]

# Protocols to check (TCP and UDP are relevant for SSH and RDP)
risky_protocols := ["tcp", "udp"]

# Check if a rule exposes risky ports from public sources
is_risky_public_rule(rule) if {
	# Source is 0.0.0.0/0 (all IPv4)
	rule.SourceCidrIp == "0.0.0.0/0"

	# Protocol is TCP, UDP, or ALL
	lower(rule.IpProtocol) in risky_protocols

	# Policy is accept (default)
	object.get(rule, "Policy", "accept") == "accept"

	# Check if any risky port is in the range
	some port in risky_ports
	helpers.port_in_range(port, rule.PortRange)
}

is_risky_public_rule(rule) if {
	# Source is ::/0 (all IPv6)
	rule.Ipv6SourceCidrIp == "::/0"

	# Protocol is TCP, UDP, or ALL
	lower(rule.IpProtocol) in risky_protocols

	# Policy is accept (default)
	object.get(rule, "Policy", "accept") == "accept"

	# Check if any risky port is in the range
	some port in risky_ports
	helpers.port_in_range(port, rule.PortRange)
}

# Check SecurityGroup resource for ingress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupIngress
	is_risky_public_rule(rule)
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
		"IpProtocol": props.IpProtocol,
		"PortRange": props.PortRange,
		"SourceCidrIp": object.get(props, "SourceCidrIp", ""),
		"Ipv6SourceCidrIp": object.get(props, "Ipv6SourceCidrIp", ""),
		"Policy": object.get(props, "Policy", "accept"),
	}
	is_risky_public_rule(ingress_rule)
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
		"IpProtocol": perm.IpProtocol,
		"PortRange": perm.PortRange,
		"SourceCidrIp": object.get(perm, "SourceCidrIp", ""),
		"Ipv6SourceCidrIp": object.get(perm, "Ipv6SourceCidrIp", ""),
		"Policy": object.get(perm, "Policy", "accept"),
	}
	is_risky_public_rule(ingress_rule)
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
