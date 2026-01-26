package infraguard.rules.aliyun.kafka_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "kafka-instance-multi-zone",
	"name": {
		"en": "Kafka Instance Multi-Zone Deployment",
		"zh": "使用多可用区的消息队列 Kafka 版实例",
	},
	"severity": "medium",
	"description": {
		"en": "Kafka instances should be deployed across multiple availability zones for high availability.",
		"zh": "使用多可用区的消息队列 Kafka 版实例，视为合规。",
	},
	"reason": {
		"en": "The Kafka instance is not configured for cross-zone deployment or multiple selected zones.",
		"zh": "Kafka 实例未配置跨可用区部署或未选择多个可用区。",
	},
	"recommendation": {
		"en": "Enable CrossZone or specify at least 2 zones in SelectedZones.",
		"zh": "启用 CrossZone 或在 SelectedZones 中指定至少 2 个可用区。",
	},
	"resource_types": ["ALIYUN::KAFKA::Instance"],
}

# Check if instance is multi-zone
is_multi_zone(resource) if {
	# Method 1: DeployOption.CrossZone is set to true
	deploy_option := object.get(resource.Properties, "DeployOption", {})
	object.get(deploy_option, "CrossZone", false) == true
}

is_multi_zone(resource) if {
	# Method 2: DeployOption.SelectedZones count >= 2
	deploy_option := object.get(resource.Properties, "DeployOption", {})
	selected_zones := object.get(deploy_option, "SelectedZones", [])
	count(selected_zones) >= 2
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "CrossZone"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
