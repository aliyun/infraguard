package infraguard.rules.aliyun.cr_repository_type_private

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "cr-repository-type-private",
	"name": {
		"en": "CR Repository Type Private",
		"zh": "容器镜像服务镜像仓库类型为私有",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that CR repositories are set to PRIVATE.",
		"zh": "确保容器镜像仓库类型设置为私有。",
	},
	"reason": {
		"en": "Public repositories can be accessed by anyone, which may lead to exposure of sensitive code or data.",
		"zh": "公开仓库可以被任何人访问，可能导致敏感代码或数据泄露。",
	},
	"recommendation": {
		"en": "Set the RepoType to 'PRIVATE' for the CR repository.",
		"zh": "将容器镜像仓库的 RepoType 设置为 'PRIVATE'。",
	},
	"resource_types": ["ALIYUN::CR::Repository"],
}

is_compliant(resource) if {
	helpers.get_property(resource, "RepoType", "PRIVATE") == "PRIVATE"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CR::Repository")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RepoType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
