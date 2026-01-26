package infraguard.rules.aliyun.rds_white_list_internet_ip_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rds-white-list-internet-ip-access-check",
	"name": {
		"en": "RDS Whitelist Internet Restriction",
		"zh": "RDS 白名单禁用公网开放"
	},
	"severity": "high",
	"description": {
		"en": "Ensures RDS security IP whitelists do not contain 0.0.0.0/0.",
		"zh": "确保 RDS 安全 IP 白名单中不包含 0.0.0.0/0。"
	},
	"reason": {
		"en": "Allowing 0.0.0.0/0 in the whitelist exposes the database to all public internet traffic.",
		"zh": "在白名单中允许 0.0.0.0/0 会使数据库暴露给所有的公网流量。"
	},
	"recommendation": {
		"en": "Remove 0.0.0.0/0 from the RDS security IP list and use specific trusted IPs.",
		"zh": "从 RDS 安全 IP 列表中移除 0.0.0.0/0，并使用特定的可信 IP。"
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	whitelist_str := helpers.get_property(resource, "SecurityIPList", "")
	whitelist := split(whitelist_str, ",")
	not has_public_ip(whitelist)
}

has_public_ip(whitelist) if {
	some ip in whitelist
	helpers.is_public_cidr(trim_space(ip))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPList"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
