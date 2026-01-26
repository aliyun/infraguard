package infraguard.rules.aliyun.oss_bucket_policy_no_any_anonymous

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-policy-no-any-anonymous",
	"name": {
		"en": "OSS bucket policy does not grant permissions to anonymous users",
		"zh": "OSS 存储空间不能为匿名账号授予任何权限",
	},
	"description": {
		"en": "OSS bucket policy does not grant any read or write permissions to anonymous users.",
		"zh": "OSS Bucket 授权策略中未授予匿名账号任何读写权限。",
	},
	"severity": "high",
	"resource_types": ["ALIYUN::OSS::Bucket"],
	"reason": {
		"en": "OSS bucket policy grants permissions to anonymous users, which may expose sensitive data.",
		"zh": "OSS Bucket 授权策略授予匿名账号权限,可能导致敏感数据泄露。",
	},
	"recommendation": {
		"en": "Remove anonymous user permissions from OSS bucket policy. Ensure Principal does not contain '*' for anonymous access.",
		"zh": "从 OSS Bucket 授权策略中移除匿名用户权限。确保 Principal 不包含'*'以避免匿名访问。",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Check if bucket has a policy
	policy := helpers.get_property(resource, "Policy", {})

	# If no policy is set, it's compliant (no anonymous access granted)
	count(policy) > 0

	# Check if policy contains statements
	statement := policy.Statement[_]

	# Check if statement grants access to anonymous users (Principal: "*")
	principal := object.get(statement, "Principal", "")
	principal == "*"
	statement.Effect == "Allow"

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Policy", "Statement"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
