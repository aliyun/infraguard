package infraguard.rules.aliyun.fc_function_settings_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "fc-function-settings-check",
	"name": {
		"en": "FC Function Settings Check",
		"zh": "函数计算中函数设置满足参数指定要求",
	},
	"severity": "medium",
	"description": {
		"en": "FC function settings should meet specified requirements for optimal performance and security.",
		"zh": "函数计算 2.0 中的函数设置满足参数指定的要求，视为合规。",
	},
	"reason": {
		"en": "The FC function settings may not meet the specified requirements.",
		"zh": "函数计算中的函数设置可能不满足指定要求。",
	},
	"recommendation": {
		"en": "Review and update function settings according to your organization's requirements.",
		"zh": "根据组织要求审查和更新函数设置。",
	},
	"resource_types": ["ALIYUN::FC::Function"],
}

# Deny rule: FC functions should have valid settings
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Function")
	handler := helpers.get_property(resource, "Handler", "")
	handler == ""
	result := {
		"id": "fc-function-settings-check",
		"resource_id": name,
		"violation_path": ["Properties", "Handler"],
		"meta": {
			"severity": "medium",
			"reason": "The function does not have valid settings configured.",
			"recommendation": "Configure proper Handler for the function.",
		},
	}
}
