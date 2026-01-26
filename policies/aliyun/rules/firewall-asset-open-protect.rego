package infraguard.rules.aliyun.firewall_asset_open_protect

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "firewall-asset-open-protect",
	"name": {
		"en": "Cloud Firewall Asset Protection Enabled",
		"zh": "云防火墙资产开启保护"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures assets are protected by Cloud Firewall.",
		"zh": "确保资产已受云防火墙保护。"
	},
	"reason": {
		"en": "Unprotected assets are vulnerable to internet-based threats.",
		"zh": "未受保护的资产容易受到来自互联网的威胁。"
	},
	"recommendation": {
		"en": "Add ALIYUN::CLOUDFW::FwSwitch resource to enable protection for all public-facing assets in Cloud Firewall.",
		"zh": "添加 ALIYUN::CLOUDFW::FwSwitch 资源以在云防火墙中为所有面向公网的资产开启保护。"
	},
	"resource_types": ["ALIYUN::CLOUDFW::FwSwitch"],
}

# ALIYUN::CLOUDFW::FwSwitch resource existence means protection is enabled
# This rule only checks if FwSwitch resources exist in the template
# If no FwSwitch resource exists, we cannot verify protection at template level
# This is a conceptual check that requires runtime verification
# We only flag violations if there are other resources that might need protection
# but no FwSwitch resources exist

# Check if template has any resources that might need firewall protection
# Exclude dummy resources like ALIYUN::ROS::WaitConditionHandle
has_resources_needing_protection if {
	some name, resource in input.Resources
	resource.Type != "ALIYUN::ROS::WaitConditionHandle"
}

# Only flag violation if there are resources but no FwSwitch
deny contains result if {
	has_resources_needing_protection
	count(helpers.resources_by_type("ALIYUN::CLOUDFW::FwSwitch")) == 0
	result := {
		"id": rule_meta.id,
		"resource_id": "",
		"violation_path": ["Resources"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
