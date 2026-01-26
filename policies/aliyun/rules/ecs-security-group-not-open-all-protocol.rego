package infraguard.rules.aliyun.ecs_security_group_not_open_all_protocol

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-not-open-all-protocol",
	"name": {
		"en": "Security Group Ingress Not Open All Protocols",
		"zh": "安全组入网设置不能有对所有协议开放的访问规则",
	},
	"severity": "high",
	"description": {
		"en": "Security group ingress rules should not allow all protocols. When the protocol type is not set to ALL, it is considered compliant.",
		"zh": "安全组入方向授权策略为允许，当协议类型未设置为 ALL 时，视为合规。如果协议类型设置为 ALL，但被优先级更高的授权策略拒绝，视为合规。",
	},
	"reason": {
		"en": "The security group has an ingress rule that allows all protocols (IpProtocol=all), which poses a security risk by allowing any type of network traffic.",
		"zh": "安全组有一条入网规则允许所有协议（IpProtocol=all），允许任何类型的网络流量，存在安全风险。",
	},
	"recommendation": {
		"en": "Restrict ingress rules to specific protocols (tcp, udp, icmp) based on actual business requirements instead of using 'all'.",
		"zh": "根据实际业务需求，将入网规则限制为特定的协议（tcp、udp、icmp），而不是使用'all'。",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupIngress", "ALIYUN::ECS::SecurityGroupIngresses"],
}

# Check if an ingress rule allows all protocols with accept policy
is_all_protocol_accept(rule) if {
	rule.IpProtocol == "all"
	object.get(rule, "Policy", "accept") == "accept"
}

# Check SecurityGroup resource for ingress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupIngress
	is_all_protocol_accept(rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIngress", format_int(i, 10), "IpProtocol"],
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
	is_all_protocol_accept(props)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "IpProtocol"],
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
	is_all_protocol_accept(perm)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Permissions", format_int(i, 10), "IpProtocol"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
