package infraguard.rules.aliyun.rds_public_connection_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rds-public-connection-and-any-ip-access-check",
	"name": {
		"en": "RDS Public Connection and Any IP Access Check",
		"zh": "开启公网 IP 的 RDS 实例白名单未对所有来源开放",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that RDS instances with public connections do not have a whitelist open to all IPs.",
		"zh": "确保开启公网 IP 的 RDS 实例白名单未设置为对所有来源 IP 开放。",
	},
	"reason": {
		"en": "An open whitelist combined with a public connection exposes the database to the internet, creating a high security risk.",
		"zh": "公网连接配合开放白名单会将数据库暴露在互联网上，造成极高的安全风险。",
	},
	"recommendation": {
		"en": "Disable public connection or restrict the IP whitelist for the RDS instance.",
		"zh": "禁用 RDS 实例的公网连接或限制 IP 白名单。",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	# If public connection is not enabled, it's compliant
	not helpers.is_true(helpers.get_property(resource, "AllocatePublicConnection", false))
}

is_compliant(resource) if {
	# If public connection is enabled, check the whitelist
	helpers.is_true(helpers.get_property(resource, "AllocatePublicConnection", false))
	whitelist_str := helpers.get_property(resource, "SecurityIPList", "")
	whitelist := split(whitelist_str, ",")
	not has_open_cidr(whitelist)
}

has_open_cidr(whitelist) if {
	some cidr in whitelist
	helpers.is_public_cidr(trim_space(cidr))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
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
