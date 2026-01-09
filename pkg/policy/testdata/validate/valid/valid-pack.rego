# Valid pack example
package infraguard.packs.aliyun.valid_test_pack

import rego.v1

pack_meta := {
	"id": "valid-test-pack",
	"name": {
		"en": "Valid Test Pack",
		"zh": "有效的测试合规包",
	},
	"description": {
		"en": "This is a valid test pack.",
		"zh": "这是一个有效的测试合规包。",
	},
	"rules": ["valid-test-rule"],
}
