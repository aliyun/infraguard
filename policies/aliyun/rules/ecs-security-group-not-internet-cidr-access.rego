package infraguard.rules.aliyun.ecs_security_group_not_internet_cidr_access

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-not-internet-cidr-access",
	"name": {
		"en": "Security Group Ingress Source IP Not Include Public IP",
		"zh": "安全组入网设置允许的来源 IP 不包含公网 IP",
	},
	"severity": "high",
	"description": {
		"en": "Security group ingress rules with accept policy should not have source IP containing public internet IPs.",
		"zh": "安全组入网方向授权策略为允许的来源 IP 地址段不包含公网 IP，视为合规。",
	},
	"reason": {
		"en": "The security group has an ingress rule that allows access from public internet IP addresses, which may expose the resources to external attacks.",
		"zh": "安全组有一条入网规则允许从公网 IP 地址访问，可能将资源暴露给外部攻击。",
	},
	"recommendation": {
		"en": "Restrict ingress source IP to private network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) unless public internet access is explicitly required.",
		"zh": "将入网来源 IP 限制为私有网络范围（10.0.0.0/8、172.16.0.0/12、192.168.0.0/16），除非确实需要公网访问。",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupIngress", "ALIYUN::ECS::SecurityGroupIngresses"],
}

# Check if a rule allows access from internet CIDR
is_internet_source_rule(rule) if {
	# Source CIDR is a public internet IP
	cidr := rule.SourceCidrIp
	cidr != ""
	helpers.is_internet_cidr(cidr)

	# Policy is accept (default)
	object.get(rule, "Policy", "accept") == "accept"
}

# Check SecurityGroup resource for ingress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupIngress
	is_internet_source_rule(rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIngress", format_int(i, 10), "SourceCidrIp"],
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
		"SourceCidrIp": object.get(props, "SourceCidrIp", ""),
		"Policy": object.get(props, "Policy", "accept"),
	}
	is_internet_source_rule(ingress_rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SourceCidrIp"],
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
		"SourceCidrIp": object.get(perm, "SourceCidrIp", ""),
		"Policy": object.get(perm, "Policy", "accept"),
	}
	is_internet_source_rule(ingress_rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Permissions", format_int(i, 10), "SourceCidrIp"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
