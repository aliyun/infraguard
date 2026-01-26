package infraguard.rules.aliyun.oss_bucket_referer_limit

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-referer-limit",
	"name": {
		"en": "OSS bucket referer hotlink protection configured",
		"zh": "OSS 存储空间 Referer 在指定的防盗链白名单中",
	},
	"description": {
		"en": "OSS bucket has referer hotlink protection enabled with a configured whitelist.",
		"zh": "OSS 存储空间开启防盗链并且 Referer 在指定白名单中。",
	},
	"severity": "low",
	"resource_types": ["ALIYUN::OSS::Bucket"],
	"reason": {
		"en": "OSS bucket does not have referer hotlink protection configured, which may lead to unauthorized access and bandwidth theft.",
		"zh": "OSS 存储空间未配置 Referer 防盗链,可能导致未授权访问和流量盗用。",
	},
	"recommendation": {
		"en": "Configure referer whitelist for OSS bucket by setting RefererConfiguration with a non-empty RefererList.",
		"zh": "通过设置 RefererConfiguration 并配置非空的 RefererList 为 OSS 存储空间配置 Referer 白名单。",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Check if referer configuration exists and has a non-empty list
	referer_config := helpers.get_property(resource, "RefererConfiguration", {})
	referer_list := object.get(referer_config, "RefererList", [])

	# Compliant if referer list is configured and not empty
	count(referer_list) == 0

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RefererConfiguration"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
