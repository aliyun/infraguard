package infraguard.rules.aliyun.ecs_instance_no_public_ip

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instance-no-public-ip",
	"name": {
		"en": "ECS instance should not bind public IP",
		"zh": "ECS 实例禁止绑定公网地址",
	},
	"description": {
		"en": "ECS instances should not directly bind IPv4 public IP or Elastic IP, considered compliant.",
		"zh": "ECS 实例没有直接绑定 IPv4 公网 IP 或弹性公网 IP，视为合规。",
	},
	"severity": "high",
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
	"reason": {
		"en": "ECS instance has a public IP bound",
		"zh": "ECS 实例绑定了公网地址",
	},
	"recommendation": {
		"en": "Use NAT Gateway or SLB for internet access instead of direct public IP binding",
		"zh": "使用 NAT 网关或 SLB 进行互联网访问，而不是直接绑定公网 IP",
	},
}

# Check if instance allocates public IP
allocates_public_ip(resource) if {
	helpers.get_property(resource, "AllocatePublicIP", false) == true
}

# Check if instance has internet bandwidth (which may result in public IP)
has_internet_bandwidth(resource) if {
	helpers.has_property(resource, "InternetMaxBandwidthOut")
	resource.Properties.InternetMaxBandwidthOut > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	allocates_public_ip(resource)
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

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	has_internet_bandwidth(resource)
	not allocates_public_ip(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InternetMaxBandwidthOut"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Check if instance is referenced by EIPAssociation via Ref
	some eip_name, eip_resource in helpers.resources_by_type("ALIYUN::VPC::EIPAssociation")
	instance_id := helpers.get_property(eip_resource, "InstanceId", "")
	helpers.is_referencing(instance_id, name)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Check if instance is referenced by EIPAssociation via GetAtt
	some eip_name, eip_resource in helpers.resources_by_type("ALIYUN::VPC::EIPAssociation")
	instance_id := helpers.get_property(eip_resource, "InstanceId", "")
	helpers.is_get_att_referencing(instance_id, name)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
