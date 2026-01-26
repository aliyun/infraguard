package infraguard.rules.aliyun.polardb_public_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "polardb-public-access-check",
	"name": {
		"en": "PolarDB Public Access Check",
		"zh": "PolarDB 实例 IP 白名单禁止设置为全网段"
	},
	"severity": "high",
	"description": {
		"en": "Ensures PolarDB IP whitelist is not set to 0.0.0.0/0.",
		"zh": "确保 PolarDB 实例 IP 白名单未设置为 0.0.0.0/0。"
	},
	"reason": {
		"en": "Setting whitelist to 0.0.0.0/0 allows access from any IP, which is a severe security risk.",
		"zh": "将白名单设置为 0.0.0.0/0 允许任何 IP 访问，这是一个严重的安全风险。"
	},
	"recommendation": {
		"en": "Configure IP whitelist to restrict access to specific IPs.",
		"zh": "配置 IP 白名单以限制特定 IP 访问。"
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_compliant(resource) if {
	whitelist := helpers.get_property(resource, "SecurityIPList", "")
	whitelist != "0.0.0.0/0"
}

is_compliant(resource) if {
	whitelist := helpers.get_property(resource, "SecurityIPList", "")
	not contains(whitelist, "0.0.0.0/0")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPList"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
