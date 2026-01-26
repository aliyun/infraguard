package infraguard.rules.aliyun.kafka_instance_public_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "kafka-instance-public-access-check",
	"name": {
		"en": "Kafka Public Access Disabled",
		"zh": "Kafka 实例禁用公网访问"
	},
	"severity": "high",
	"description": {
		"en": "Ensures Kafka instances do not have public network access.",
		"zh": "确保 Kafka 实例未开启公网访问。"
	},
	"reason": {
		"en": "Exposing Kafka to the public internet is a significant security risk.",
		"zh": "将 Kafka 暴露在公网会带来重大的安全风险。"
	},
	"recommendation": {
		"en": "Disable the public endpoint for the Kafka instance.",
		"zh": "禁用 Kafka 实例的公网端点。"
	},
	"resource_types": ["ALIYUN::KAFKA::Instance"],
}

is_compliant(resource) if {
	# In ROS, check DeployType or similar properties
	# 4: VPC, 5: Public
	type := helpers.get_property(resource, "DeployType", 4)
	type != 5
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KAFKA::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeployType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
