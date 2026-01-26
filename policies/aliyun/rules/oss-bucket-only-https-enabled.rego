package infraguard.rules.aliyun.oss_bucket_only_https_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-only-https-enabled",
	"name": {
		"en": "OSS Bucket Only HTTPS Enabled",
		"zh": "OSS 存储桶开启仅允许 HTTPS 访问",
	},
	"severity": "high",
	"description": {
		"en": "OSS bucket should have a policy that denies non-HTTPS requests to ensure data transport security.",
		"zh": "OSS 存储桶应配置仅允许 HTTPS 访问的策略，以确保数据传输安全。",
	},
	"reason": {
		"en": "The OSS bucket allows non-HTTPS requests, which may lead to data interception or tampering during transport.",
		"zh": "OSS 存储桶允许非 HTTPS 请求，可能导致数据在传输过程中被窃听或篡改。",
	},
	"recommendation": {
		"en": "Configure a bucket policy that denies requests where 'acs:SecureTransport' is false.",
		"zh": "配置存储桶策略，拒绝 'acs:SecureTransport' 为 false 的请求。",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

# Check if the bucket has a policy that enforces HTTPS
is_only_https_enabled(resource) if {
	policy := helpers.get_property(resource, "Policy", {})
	statements := object.get(policy, "Statement", [])
	some statement in statements
	statement.Effect == "Deny"

	# Check for SecureTransport condition
	condition := object.get(statement, "Condition", {})
	bool_cond := object.get(condition, "Bool", {})
	secure_transport := object.get(bool_cond, "acs:SecureTransport", null)
	has_false_value(secure_transport)
}

has_false_value(val) if {
	val == "false"
}

has_false_value(val) if {
	val == false
}

has_false_value(val) if {
	is_array(val)
	some item in val
	item_is_false(item)
}

item_is_false(v) if {
	v == "false"
}

item_is_false(v) if {
	v == false
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_only_https_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Policy"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
