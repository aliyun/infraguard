package infraguard.rules.aliyun.security_center_version_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "security-center-version-check",
	"name": {
		"en": "Security Center Version Check",
		"zh": "云安全中心版本检测",
	},
	"severity": "medium",
	"description": {
		"en": "Security Center should be at a version that provides sufficient protection features.",
		"zh": "云安全中心版本满足要求，视为合规。",
	},
	"reason": {
		"en": "A lower version of Security Center may not provide advanced threat detection and protection capabilities.",
		"zh": "较低版本的云安全中心可能无法提供先进的威胁检测和防御能力。",
	},
	"recommendation": {
		"en": "Upgrade Security Center to a higher version (e.g., Enterprise or Ultimate).",
		"zh": "将云安全中心升级到更高版本（如企业版或旗舰版）。",
	},
	"resource_types": ["ALIYUN::ThreatDetection::Instance"],
}

# VersionCode values:
# level2: Enterprise Edition
# level3: Premium version
# level7: Antivirus Edition
# level8: Ultimate
# level10: Purchase value-added services only

is_compliant_version(resource) if {
	version := helpers.get_property(resource, "VersionCode", "")
	version == "level3" # Premium version
}

is_compliant_version(resource) if {
	version := helpers.get_property(resource, "VersionCode", "")
	version == "level8" # Ultimate
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant_version(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VersionCode"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
