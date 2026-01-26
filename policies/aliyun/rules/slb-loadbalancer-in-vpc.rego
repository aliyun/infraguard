package infraguard.rules.aliyun.slb_loadbalancer_in_vpc

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-loadbalancer-in-vpc",
	"name": {
		"en": "SLB in VPC Check",
		"zh": "强制 SLB 部署在 VPC 环境中"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures SLB instances are deployed within a Virtual Private Cloud (VPC).",
		"zh": "确保 SLB 实例部署在专有网络（VPC）中。"
	},
	"reason": {
		"en": "Classic network is deprecated and offers less security and isolation than VPC.",
		"zh": "经典网络已弃用，其安全性和隔离性均不如 VPC。"
	},
	"recommendation": {
		"en": "Create SLB instances within a VPC.",
		"zh": "在 VPC 内创建 SLB 实例。"
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

is_compliant(resource) if {
	helpers.has_property(resource, "VpcId")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
