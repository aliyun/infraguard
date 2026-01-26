package infraguard.rules.aliyun.alidns_domain_regex_match

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "alidns-domain-regex-match",
	"name": {
		"en": "Alibaba Cloud DNS Domain Names Match Naming Convention",
		"zh": "阿里云解析域名符合命名规范",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that Alibaba Cloud DNS domain names match the specified naming convention regex.",
		"zh": "域名符合参数指定的命名规范正则，视为合规。",
	},
	"reason": {
		"en": "Domain name does not match the specified naming convention regex.",
		"zh": "域名不符合参数指定的命名规范正则。",
	},
	"recommendation": {
		"en": "Rename the domain to match the specified naming convention.",
		"zh": "请修改域名以符合指定的命名规范。",
	},
	"resource_types": ["ALIYUN::DNS::Domain"],
}

# Default regex pattern for domain names
default_regex_pattern := "^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$"

# Get regex pattern from parameters or use default
get_regex_pattern := input.rule_parameters.domain_name_regex_pattern if {
	input.rule_parameters.domain_name_regex_pattern != ""
} else := default_regex_pattern

# Check if domain name matches the regex pattern
domain_name_matches_regex(domain_name, pattern) if {
	regex.match(pattern, domain_name)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::DNS::Domain")

	domain_name := resource.Properties.DomainName
	pattern := get_regex_pattern

	not domain_name_matches_regex(domain_name, pattern)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DomainName"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
