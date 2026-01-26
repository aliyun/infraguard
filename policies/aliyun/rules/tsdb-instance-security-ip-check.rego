package infraguard.rules.aliyun.tsdb_instance_security_ip_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "tsdb-instance-security-ip-check",
	"name": {
		"en": "TSDB Instance Does Not Allow Any IP Access",
		"zh": "TSDB 实例安全白名单检测",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that TSDB instances do not have security whitelists that allow all IPs.",
		"zh": "TSDB 实例没有开启任意 IP 访问，视为合规。",
	},
	"reason": {
		"en": "TSDB instance allows access from any IP address, which is a security risk.",
		"zh": "TSDB 实例开启任意 IP 访问，存在安全风险。",
	},
	"recommendation": {
		"en": "Configure security whitelist to restrict access to specific IPs.",
		"zh": "请配置安全白名单以限制特定 IP 访问。",
	},
	"resource_types": ["ALIYUN::TSDB::HiTSDBInstance"],
}

# Check if whitelist allows any IP
allows_any_ip(whitelist) if {
	count(whitelist) == 1
	whitelist[0] == "0.0.0.0/0"
}

allows_any_ip(whitelist) if {
	count(whitelist) == 1
	whitelist[0] == "0.0.0.0"
}

allows_any_ip(whitelist) := false if {
	count(whitelist) != 1
}

allows_any_ip(whitelist) := false if {
	count(whitelist) == 1
	whitelist[0] != "0.0.0.0/0"
	whitelist[0] != "0.0.0.0"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::TSDB::HiTSDBInstance")

	whitelist := resource.Properties.SecurityIpList
	allows_any_ip(whitelist)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIpList"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
