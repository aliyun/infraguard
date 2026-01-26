package infraguard.rules.aliyun.rocketmq_v5_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rocketmq-v5-instance-multi-zone",
	"name": {
		"en": "RocketMQ 5.0 Instance Multi-Zone Deployment",
		"zh": "使用多可用区的消息队列 RocketMQ 5.0 版实例",
	},
	"severity": "medium",
	"description": {
		"en": "RocketMQ 5.0 instances should be deployed in Cluster HA mode which supports multi-zone availability.",
		"zh": "使用多可用区的消息队列 RocketMQ 5.0 版实例，视为合规。",
	},
	"reason": {
		"en": "The RocketMQ 5.0 instance is not configured with Cluster HA mode.",
		"zh": "RocketMQ 5.0 实例未配置为高可用集群模式。",
	},
	"recommendation": {
		"en": "Set SubSeriesCode to 'cluster_ha'.",
		"zh": "将 SubSeriesCode 设置为'cluster_ha'。",
	},
	"resource_types": ["ALIYUN::ROCKETMQ5::Instance"],
}

# Check if instance is multi-zone (cluster_ha)
is_multi_zone(resource) if {
	resource.Properties.SubSeriesCode == "cluster_ha"
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SubSeriesCode"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
