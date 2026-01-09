package infraguard.rules.aliyun.ecs_running_instance_no_public_ip

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-running-instance-no-public-ip",
	"name": {
		"en": "ECS Instance No Public IP",
		"zh": "ECS 实例不分配公网 IP",
	},
	"severity": "high",
	"description": {
		"en": "ECS instances should not have a public IP address to reduce direct internet exposure.",
		"zh": "ECS 实例不应分配公网 IP，以减少直接暴露在互联网上的风险。",
	},
	"reason": {
		"en": "Public IP addresses allow direct access from the internet, increasing the attack surface.",
		"zh": "分配公网 IP 会使实例直接暴露在互联网上，增加了攻击面。",
	},
	"recommendation": {
		"en": "Remove public IP assignment by setting AllocatePublicIP to false or using a NAT gateway for egress.",
		"zh": "通过将 AllocatePublicIP 设置为 false 或使用 NAT 网关来取消分配公网 IP。",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

# Check if the instance has a public IP allocated
has_public_ip(resource) if {
	helpers.get_property(resource, "AllocatePublicIP", false) == true
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	has_public_ip(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AllocatePublicIP"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
