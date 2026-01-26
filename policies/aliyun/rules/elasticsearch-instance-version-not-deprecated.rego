package infraguard.rules.aliyun.elasticsearch_instance_version_not_deprecated

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "elasticsearch-instance-version-not-deprecated",
	"name": {
		"en": "Elasticsearch Instance Does Not Use Deprecated Version",
		"zh": "未使用不推荐的 Elasticsearch 实例版本",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Elasticsearch instances are not using deprecated or EOL versions.",
		"zh": "Elasticsearch 实例所使用的版本未在参数指定的不推荐版本范围内，视为合规。",
	},
	"reason": {
		"en": "Using deprecated Elasticsearch versions may have security vulnerabilities and lack support.",
		"zh": "使用不推荐的 Elasticsearch 版本可能存在安全漏洞且缺乏支持。",
	},
	"recommendation": {
		"en": "Upgrade to a supported Elasticsearch version.",
		"zh": "请升级到支持的 Elasticsearch 版本。",
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

# Default deprecated versions (major versions that are EOL)
default deprecated_versions := [
	"5.5.3",
	"5.6.16",
	"6.3",
	"6.7",
	"7.0",
]

# Get deprecated versions from parameters or use default
get_deprecated_versions := deprecated_versions if {
	params := object.get(input, "rule_parameters", {})
	val := object.get(params, "deprecated_versions", "")
	val == ""
}

get_deprecated_versions := versions if {
	params := object.get(input, "rule_parameters", {})
	val := object.get(params, "deprecated_versions", "")
	val != ""
	versions := val
}

# Check if a version is deprecated
is_deprecated_version(version) if {
	some deprecated in get_deprecated_versions
	startswith(version, deprecated)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")

	version := resource.Properties.Version

	is_deprecated_version(version)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Version"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
