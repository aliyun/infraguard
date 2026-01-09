# Invalid rule - invalid severity value
package infraguard.rules.aliyun.invalid_severity_rule

import rego.v1

rule_meta := {
	"id": "invalid-severity-rule",
	"name": {"en": "Invalid Severity Rule"},
	"severity": "critical",
	"reason": {"en": "Resource does not meet requirements."},
	"resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
	false
	result := {}
}
