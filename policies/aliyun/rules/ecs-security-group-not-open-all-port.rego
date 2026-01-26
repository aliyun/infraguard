package infraguard.rules.aliyun.ecs_security_group_not_open_all_port

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-not-open-all-port",
	"name": {
		"en": "Security Group Ingress Not Open All Ports",
		"zh": "安全组入网设置中不能有对所有端口开放的访问规则",
	},
	"severity": "high",
	"description": {
		"en": "Security group ingress rules should not allow all ports. When the port range is not set to -1/-1, it is considered compliant.",
		"zh": "安全组入方向授权策略为允许，当端口范围未设置为-1/-1 时，视为合规。如果端口范围设置为-1/-1，但被优先级更高的授权策略拒绝，视为合规。",
	},
	"reason": {
		"en": "The security group has an ingress rule that allows all ports (PortRange=-1/-1), which poses a security risk by allowing access to any port.",
		"zh": "安全组有一条入网规则允许所有端口（PortRange=-1/-1），允许访问任何端口，存在安全风险。",
	},
	"recommendation": {
		"en": "Restrict ingress rules to specific port ranges based on actual business requirements instead of using '-1/-1' (all ports).",
		"zh": "根据实际业务需求，将入网规则限制为特定的端口范围，而不是使用'-1/-1'（所有端口）。",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupIngress", "ALIYUN::ECS::SecurityGroupIngresses"],
}

# Check if an ingress rule allows all ports with accept policy
is_all_port_accept(rule) if {
	rule.PortRange == "-1/-1"
	object.get(rule, "Policy", "accept") == "accept"
}

# Check SecurityGroup resource for ingress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupIngress
	is_all_port_accept(rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIngress", format_int(i, 10), "PortRange"],
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
	is_all_port_accept(props)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "PortRange"],
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
	is_all_port_accept(perm)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Permissions", format_int(i, 10), "PortRange"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
