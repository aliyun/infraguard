package infraguard.rules.aliyun.alb_acl_public_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:alb-acl-public-access-check",
	"name": {
		"en": "ALB ACL Does Not Allow Public Access",
		"zh": "ALB 访问控制列表不允许配置所有地址段",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ALB access control lists do not contain 0.0.0.0/0 (allowing all IPs).",
		"zh": "确保 ALB 访问控制列表不包含 0.0.0.0/0（允许所有 IP）。",
	},
	"reason": {
		"en": "Setting the ACL to 0.0.0.0/0 allows any IP to access the load balancer, significantly increasing security risks.",
		"zh": "将 ACL 设置为 0.0.0.0/0 允许任何 IP 访问负载均衡器，大大增加了安全风险。",
	},
	"recommendation": {
		"en": "Restrict the ACL to specific IP ranges instead of allowing all IPs.",
		"zh": "将 ACL 限制为特定的 IP 范围，而不是允许所有 IP。",
	},
	"resource_types": ["ALIYUN::ALB::Acl"],
}

# Check if ACL contains 0.0.0.0/0
contains_public_cidr(acl_resource) if {
	acl_entries := helpers.get_property(acl_resource, "AclEntries", [])
	some entry in acl_entries
	cidr := entry.Entry
	cidr == "0.0.0.0/0"
}

contains_public_cidr(acl_resource) if {
	acl_entries := helpers.get_property(acl_resource, "AclEntries", [])
	some entry in acl_entries
	cidr := entry.Entry
	cidr == "0.0.0.0"
}

is_compliant(resource) if {
	not contains_public_cidr(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::Acl")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AclEntries"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
