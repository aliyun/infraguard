package infraguard.rules.aliyun.vpc_network_acl_not_empty

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "vpc-network-acl-not-empty",
	"name": {
		"en": "VPC Network ACL Not Empty",
		"zh": "专有网络 ACL 不为空条目"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures VPC Network ACLs have at least one rule configured.",
		"zh": "确保 VPC 网络 ACL 至少配置了一条规则。"
	},
	"reason": {
		"en": "An empty ACL provides no security filtering, which might lead to unintended access.",
		"zh": "空的 ACL 不提供任何安全过滤，可能导致非预期的访问。"
	},
	"recommendation": {
		"en": "Add ingress and egress rules to the VPC Network ACL.",
		"zh": "为 VPC 网络 ACL 添加进方向和出方向规则。"
	},
	"resource_types": ["ALIYUN::VPC::NetworkAcl"],
}

is_compliant(resource) if {
	entries := helpers.get_property(resource, "IngressAclEntries", [])
	count(entries) > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::NetworkAcl")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "IngressAclEntries"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
