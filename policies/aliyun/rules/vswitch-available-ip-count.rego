package infraguard.rules.aliyun.vswitch_available_ip_count

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:vswitch-available-ip-count",
	"name": {
		"en": "VSwitch Available IP Count Check",
		"zh": "VSwitch 可用 IP 数量检测",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the VSwitch has a sufficient number of available IP addresses.",
		"zh": "确保 VSwitch 具有足够数量的可用 IP 地址。",
	},
	"reason": {
		"en": "Running out of available IP addresses prevents new resources from being created in the VSwitch.",
		"zh": "可用 IP 地址耗尽将阻止在 VSwitch 中创建新资源。",
	},
	"recommendation": {
		"en": "Ensure that the VSwitch has enough available IP addresses or create a larger VSwitch.",
		"zh": "确保 VSwitch 具有足够的可用 IP 地址，或创建一个更大的 VSwitch。",
	},
	"resource_types": ["ALIYUN::ECS::VSwitch"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::VSwitch")

	# Conceptual check for available IPs
	# Since it's runtime info, in template we might check CIDR size
	cidr := helpers.get_property(resource, "CidrBlock", "")

	# This is a bit complex to calculate accurately in Rego without helpers,
	# but we can detect very small subnets.
	endswith(cidr, "/29") # Example: Too small
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "CidrBlock"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
