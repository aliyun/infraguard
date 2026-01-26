package infraguard.rules.aliyun.sg_public_access_check

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "sg-public-access-check",
	"name": {
		"en": "Security Group Ingress Valid",
		"zh": "安全组入网设置有效",
	},
	"severity": "high",
	"description": {
		"en": "Security group ingress rules should not allow all ports (-1/-1) from all sources (0.0.0.0/0) simultaneously.",
		"zh": "安全组入方向授权策略为允许，当端口范围-1/-1 和授权对象 0.0.0.0/0 未同时出现，或者被优先级更高的授权策略拒绝，视为合规。",
	},
	"reason": {
		"en": "The security group has an ingress rule that allows all ports from all sources (0.0.0.0/0 with port range -1/-1), which poses a critical security risk.",
		"zh": "安全组有一条入网规则同时允许所有端口（-1/-1）和所有来源（0.0.0.0/0），存在严重安全风险。",
	},
	"recommendation": {
		"en": "Either restrict the source IP range to specific CIDR blocks or limit the port range to specific ports based on actual business requirements.",
		"zh": "根据实际业务需求，将来源 IP 范围限制为特定的 CIDR 块，或将端口范围限制为特定的端口。",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupIngress", "ALIYUN::ECS::SecurityGroupIngresses"],
}

# Check if an ingress rule is a public access rule (all ports from all sources)
is_public_access(rule) if {
	rule.PortRange == "-1/-1"
	rule.SourceCidrIp == "0.0.0.0/0"
	object.get(rule, "Policy", "accept") == "accept"
}

is_public_access(rule) if {
	rule.PortRange == "-1/-1"
	rule.Ipv6SourceCidrIp == "::/0"
	object.get(rule, "Policy", "accept") == "accept"
}

# Check SecurityGroup resource for ingress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupIngress
	is_public_access(rule)
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
	is_public_access(ingress_rule)
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
	is_public_access(ingress_rule)
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
