package infraguard.rules.aliyun.polardb_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "polardb-public-and-any-ip-access-check",
	"name": {
		"en": "PolarDB Public and Any IP Access Check",
		"zh": "PolarDB 公网及全网 IP 访问检测",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that PolarDB clusters do not have public endpoints and are not open to any IP address (0.0.0.0/0).",
		"zh": "确保 PolarDB 集群没有公网端点，并且未对任何 IP 地址(0.0.0.0/0)开放。",
	},
	"reason": {
		"en": "Exposing a database to the public internet or any IP address is a significant security risk.",
		"zh": "将数据库暴露给公网或任何 IP 地址是重大的安全风险。",
	},
	"recommendation": {
		"en": "Disable public endpoints for the PolarDB cluster and restrict the white list to specific IP addresses.",
		"zh": "为 PolarDB 集群禁用公网端点，并将白名单限制为特定的 IP 地址。",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")

	# Check if SecurityIPList contains 0.0.0.0/0 (any IP access)
	whitelist := helpers.get_property(resource, "SecurityIPList", "")
	whitelist == "0.0.0.0/0"
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPList"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")

	# Check if SecurityIPList contains 0.0.0.0/0 in comma-separated list
	whitelist := helpers.get_property(resource, "SecurityIPList", "")
	contains(whitelist, "0.0.0.0/0")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPList"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
