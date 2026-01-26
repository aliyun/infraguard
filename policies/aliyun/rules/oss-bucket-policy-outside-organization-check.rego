package infraguard.rules.aliyun.oss_bucket_policy_outside_organization_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "oss-bucket-policy-outside-organization-check",
	"name": {
		"en": "OSS Bucket Policy No Outside Organization Access",
		"zh": "OSS 存储桶策略未给组织外授权"
	},
	"severity": "high",
	"description": {
		"en": "Ensures OSS bucket policies do not grant access to principals outside of the organization.",
		"zh": "确保 OSS 存储桶策略未授予组织外部的主体访问权限。"
	},
	"reason": {
		"en": "Granting access to external principals can lead to data leaks outside the organization's control.",
		"zh": "授予外部主体访问权限可能导致数据在组织控制之外泄露。"
	},
	"recommendation": {
		"en": "Ensure all principals in the bucket policy are within the authorized organization.",
		"zh": "确保存储桶策略中的所有主体均属于获得授权的组织。"
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

# Simplified implementation for IaC: Check if any Principal is '*' without a restrictive Condition
# or if Principal is an external account ID (not easily detectable in pure IaC without context).
# Here we check for '*' in Allow statements.
is_compliant(resource) if {
	policy := helpers.get_property(resource, "Policy", {})
	statements := object.get(policy, "Statement", [])
	not has_external_allow(statements)
}

has_external_allow(statements) if {
	some statement in statements
	statement.Effect == "Allow"
	principal := object.get(statement, "Principal", [])
	is_public_principal(principal)
}

is_public_principal("*") := true

is_public_principal(p) if {
	is_array(p)
	some item in p
	item == "*"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Policy"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
