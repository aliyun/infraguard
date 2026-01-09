# Invalid rule - missing name field
package infraguard.rules.aliyun.missing_name_rule

import rego.v1

rule_meta := {
	"id": "missing-name-rule",
	"severity": "high",
	"reason": {"en": "Resource does not meet requirements."},
	"resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
	false
	result := {}
}
