# Valid rule example
package infraguard.rules.aliyun.valid_test_rule

import rego.v1

rule_meta := {
	"id": "valid-test-rule",
	"name": {
		"en": "Valid Test Rule",
		"zh": "有效的测试规则",
	},
	"severity": "high",
	"description": {
		"en": "This is a valid test rule.",
		"zh": "这是一个有效的测试规则。",
	},
	"reason": {
		"en": "Resource does not meet requirements.",
		"zh": "资源不符合要求。",
	},
	"recommendation": {
		"en": "Fix the configuration.",
		"zh": "修复配置。",
	},
	"resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
	input.test == true
	result := {
		"id": rule_meta.id,
		"resource_id": "test",
		"violation_path": ["test"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
		},
	}
}
