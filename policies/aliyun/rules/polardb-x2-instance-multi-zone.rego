package infraguard.rules.aliyun.polardb_x2_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:polardb-x2-instance-multi-zone",
	"name": {
		"en": "PolarDB-X 2.0 Instance Multi-Zone Deployment",
		"zh": "PolarDB-X 2.0 实例多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "PolarDB-X 2.0 instances should be deployed across 3 availability zones.",
		"zh": "PolarDB-X 2.0 实例应部署在 3 个可用区。",
	},
	"reason": {
		"en": "The PolarDB-X 2.0 instance is configured with single-zone topology.",
		"zh": "PolarDB-X 2.0 实例配置为单可用区拓扑。",
	},
	"recommendation": {
		"en": "Set TopologyType to '3azones'.",
		"zh": "将 TopologyType 设置为'3azones'。",
	},
	"resource_types": ["ALIYUN::PolarDBX::DBInstance"],
}

# Check if instance is multi-zone (3azones)
is_multi_zone(resource) if {
	resource.Properties.TopologyType == "3azones"
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TopologyType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
