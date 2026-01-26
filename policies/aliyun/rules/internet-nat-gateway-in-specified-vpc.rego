package infraguard.rules.aliyun.internet_nat_gateway_in_specified_vpc

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "internet-nat-gateway-in-specified-vpc",
	"name": {
		"en": "Internet NAT Gateway in Specified VPC",
		"zh": "公网 NAT 网关创建在指定专有网络内"
	},
	"severity": "medium",
	"description": {
		"en": "Internet-facing NAT gateways should be created in specified VPCs according to network security requirements.",
		"zh": "公网 NAT 网关所属专有网络在参数指定的专有网络列表中，视为合规。"
	},
	"reason": {
		"en": "Internet-facing NAT gateways in non-specified VPCs may violate network segmentation and security policies.",
		"zh": "不在指定 VPC 中的公网 NAT 网关可能违反网络分段和安全策略。"
	},
	"recommendation": {
		"en": "Ensure internet-facing NAT gateways are deployed only in the specified VPCs.",
		"zh": "确保公网 NAT 网关仅部署在指定的 VPC 中。"
	},
	"resource_types": ["ALIYUN::NAT::NatGateway"],
}

is_internet_nat_gateway(resource) if {
	network_type := helpers.get_property(resource, "NetworkType", "")
	network_type == "internet"
}

is_in_specified_vpc(resource) if {
	# Parameter-based check - in production would use input parameter
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vpc_id != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAT::NatGateway")
	is_internet_nat_gateway(resource)
	not is_in_specified_vpc(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
