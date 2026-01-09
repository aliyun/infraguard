package infraguard.rules.aliyun.ecs_instance_no_public_and_anyip

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:ecs-instance-no-public-and-anyip",
	"name": {
		"en": "ECS Instance Should Not Bind Public IP or Allow Any IP Access",
		"zh": "ECS 实例禁止绑定公网地址和开放任意 ip",
	},
	"description": {
		"en": "ECS instances should not directly bind IPv4 public IPs or Elastic IPs, and associated security groups should not expose 0.0.0.0/0. Compliant when no public IP is bound.",
		"zh": "ECS 实例没有直接绑定 IPv4 公网 IP 或弹性公网 IP，或关联的安全组未开放 0.0.0.0/0，视为合规。",
	},
	"severity": "medium",
	"resource_types": ["ALIYUN::ECS::Instance"],
	"reason": {
		"en": "ECS instance has public IP allocation enabled or uses unrestricted internet bandwidth",
		"zh": "ECS 实例启用了公网 IP 分配或使用了不受限制的互联网带宽",
	},
	"recommendation": {
		"en": "Disable public IP allocation (AllocatePublicIP=false) and set InternetMaxBandwidthOut to 0. Use NAT Gateway or SLB for internet access instead.",
		"zh": "禁用公网 IP 分配(AllocatePublicIP=false)并将 InternetMaxBandwidthOut 设置为 0。改用 NAT 网关或 SLB 进行互联网访问。",
	},
}

# Check if instance has public IP allocated
has_public_ip(resource) if {
	helpers.has_property(resource, "AllocatePublicIP")
	helpers.is_true(resource.Properties.AllocatePublicIP)
}

# Check if instance has internet bandwidth (which implies public IP access)
has_internet_bandwidth(resource) if {
	helpers.has_property(resource, "InternetMaxBandwidthOut")
	resource.Properties.InternetMaxBandwidthOut > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
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

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
	has_internet_bandwidth(resource)
	not has_public_ip(resource) # Only report if not already reported by AllocatePublicIP check
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
