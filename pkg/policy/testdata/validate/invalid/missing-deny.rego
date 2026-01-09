# Invalid rule - missing deny rule
package infraguard.rules.aliyun.missing_deny_rule

import rego.v1

rule_meta := {
	"id": "missing-deny-rule",
	"name": {"en": "Missing Deny Rule"},
	"severity": "high",
	"reason": {"en": "Resource does not meet requirements."},
	"resource_types": ["ALIYUN::ECS::Instance"],
}
