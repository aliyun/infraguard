package infraguard.rules.aliyun.slb_acl_public_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:slb-acl-public-access-check",
	"name": {
		"en": "SLB ACL Public Access Check",
		"zh": "CLB 访问控制列表不配置所有地址段",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that SLB ACLs do not contain 0.0.0.0/0 to prevent unrestricted public access.",
		"zh": "确保 CLB 访问控制列表中不包含 0.0.0.0/0，以防止无限制的公网访问。",
	},
	"reason": {
		"en": "Allowing 0.0.0.0/0 in an ACL bypasses the security benefits of access control, potentially exposing services to attacks.",
		"zh": "在 ACL 中允许 0.0.0.0/0 会绕过访问控制的安全保障，使服务可能遭受攻击。",
	},
	"recommendation": {
		"en": "Remove 0.0.0.0/0 from the SLB ACL entries and replace it with specific IP ranges.",
		"zh": "从 CLB 访问控制列表条目中移除 0.0.0.0/0，并替换为特定的 IP 范围。",
	},
	"resource_types": ["ALIYUN::SLB::AccessControl"],
}

is_compliant(resource) if {
	entries := helpers.get_property(resource, "AclEntries", [])
	not has_open_entry(entries)
}

has_open_entry(entries) if {
	some entry in entries
	helpers.is_public_cidr(entry.Entry)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::AccessControl")
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
