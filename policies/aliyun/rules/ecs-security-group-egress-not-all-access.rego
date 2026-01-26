package infraguard.rules.aliyun.ecs_security_group_egress_not_all_access

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-egress-not-all-access",
	"name": {
		"en": "Security Group Egress Not Set to All Access",
		"zh": "安全组出方向未设置为全通",
	},
	"severity": "high",
	"description": {
		"en": "Security group egress direction should not be set to allow all access (all protocols, all ports, all destinations).",
		"zh": "安全组出网方向未设置为全通，视为合规。",
	},
	"reason": {
		"en": "The security group has an egress rule that allows all access (all protocols to all destinations), which poses a security risk.",
		"zh": "安全组有一条出网规则允许全通访问（所有协议到所有目标），存在安全风险。",
	},
	"recommendation": {
		"en": "Restrict egress rules to specific protocols, ports, and destination IP ranges based on actual business requirements.",
		"zh": "根据实际业务需求，将出网规则限制为特定的协议、端口和目标 IP 范围。",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupEgress", "ALIYUN::ECS::SecurityGroupEgresses"],
}

# Check if an egress rule allows all access
is_all_access_egress(rule) if {
	rule.IpProtocol == "all"
	rule.PortRange == "-1/-1"
	rule.DestCidrIp == "0.0.0.0/0"
	object.get(rule, "Policy", "accept") == "accept"
}

is_all_access_egress(rule) if {
	rule.IpProtocol == "all"
	rule.PortRange == "-1/-1"
	rule.Ipv6DestCidrIp == "::/0"
	object.get(rule, "Policy", "accept") == "accept"
}

# Check SecurityGroup resource for egress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupEgress
	is_all_access_egress(rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupEgress", format_int(i, 10)],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

# Check SecurityGroupEgress resource
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroupEgress")
	props := resource.Properties
	egress_rule := {
		"IpProtocol": props.IpProtocol,
		"PortRange": props.PortRange,
		"DestCidrIp": object.get(props, "DestCidrIp", ""),
		"Ipv6DestCidrIp": object.get(props, "Ipv6DestCidrIp", ""),
		"Policy": object.get(props, "Policy", "accept"),
	}
	is_all_access_egress(egress_rule)
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

# Check SecurityGroupEgresses resource
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroupEgresses")
	some i, perm in resource.Properties.Permissions
	egress_rule := {
		"IpProtocol": perm.IpProtocol,
		"PortRange": perm.PortRange,
		"DestCidrIp": object.get(perm, "DestCidrIp", ""),
		"Ipv6DestCidrIp": object.get(perm, "Ipv6DestCidrIp", ""),
		"Policy": object.get(perm, "Policy", "accept"),
	}
	is_all_access_egress(egress_rule)
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
