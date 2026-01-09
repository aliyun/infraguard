package infraguard.rules.aliyun.sls_project_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:sls-project-multi-zone",
	"name": {
		"en": "SLS Project Zone-Redundant Storage",
		"zh": "SLS 项目使用同城冗余存储",
	},
	"severity": "medium",
	"description": {
		"en": "SLS projects should use zone-redundant storage (ZRS) for high availability and data durability.",
		"zh": "SLS 项目应使用同城冗余存储（ZRS）以实现高可用性和数据持久性。",
	},
	"reason": {
		"en": "The SLS project does not use zone-redundant storage, which may affect data availability.",
		"zh": "SLS 项目未使用同城冗余存储，可能影响数据可用性。",
	},
	"recommendation": {
		"en": "Enable zone-redundant storage by setting DataRedundancyType to 'ZRS' when creating the project.",
		"zh": "在创建项目时通过将 DataRedundancyType 设置为'ZRS'来启用同城冗余存储。",
	},
	"resource_types": ["ALIYUN::SLS::Project"],
}

# Check if project has ZRS enabled
has_zrs_enabled(resource) if {
	redundancy_type := helpers.get_property(resource, "DataRedundancyType", "LRS")
	redundancy_type == "ZRS"
}

# Deny rule: SLS projects should have ZRS enabled
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLS::Project")
	not has_zrs_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DataRedundancyType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
