package infraguard.rules.aliyun.oss_bucket_authorize_specified_ip

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:oss-bucket-authorize-specified-ip",
	"name": {
		"en": "OSS Bucket Authorize Specified IP",
		"zh": "OSS 存储桶策略授权特定 IP"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures OSS bucket policies restrict access to specified IP ranges.",
		"zh": "确保 OSS 存储桶策略限制了特定 IP 范围的访问。"
	},
	"reason": {
		"en": "Restricting access by IP helps prevent unauthorized access even if credentials are compromised.",
		"zh": "通过 IP 限制访问有助于防止在凭据泄露时发生未经授权的访问。"
	},
	"recommendation": {
		"en": "Add IP restriction conditions (acs:SourceIp) to the OSS bucket policy.",
		"zh": "在 OSS 存储桶策略中添加 IP 限制条件（acs:SourceIp）。"
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

is_compliant(resource) if {
	policy := helpers.get_property(resource, "Policy", {})
	statements := object.get(policy, "Statement", [])
	some statement in statements
	condition := object.get(statement, "Condition", {})
	ip_address := object.get(condition, "IpAddress", {})

	# Check for acs:SourceIp in the IpAddress condition
	object.get(ip_address, "acs:SourceIp", null) != null
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
