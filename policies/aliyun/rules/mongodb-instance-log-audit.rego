package infraguard.rules.aliyun.mongodb_instance_log_audit

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:mongodb-instance-log-audit",
	"name": {
		"en": "MongoDB Instance Log Audit Enabled",
		"zh": "MongoDB 实例开启操作日志审计"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures MongoDB instances have audit logging enabled.",
		"zh": "确保 MongoDB 实例开启了操作日志审计。"
	},
	"reason": {
		"en": "Audit logs are critical for security monitoring and compliance auditing.",
		"zh": "审计日志对于安全监控和合规审计至关重要。"
	},
	"recommendation": {
		"en": "Enable audit logging for the MongoDB instance.",
		"zh": "为 MongoDB 实例开启操作日志审计。"
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

is_compliant(resource) if {
	audit_options := helpers.get_property(resource, "AuditPolicyOptions", {})
	status := object.get(audit_options, "AuditStatus", "disabled")
	status == "enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AuditPolicyOptions", "AuditStatus"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
