package infraguard.rules.aliyun.ots_instance_multi_zone

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ots-instance-multi-zone",
	"name": {
		"en": "OTS Instance Zone-Redundant Storage",
		"zh": "使用同城冗余的 OTS 实例"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Tablestore (OTS) instances use zone-redundant storage for high availability.",
		"zh": "确保 Tablestore（OTS）实例使用同城冗余存储以实现高可用性。"
	},
	"reason": {
		"en": "Zone-redundant storage provides higher availability and protects against zone-level failures.",
		"zh": "同城冗余存储提供更高的可用性，并防止可用区级别的故障。"
	},
	"recommendation": {
		"en": "Use zone-redundant Tablestore instances for critical workloads.",
		"zh": "为关键工作负载使用同城冗余的 Tablestore 实例。"
	},
	"resource_types": ["ALIYUN::OTS::Instance"],
}

is_compliant(resource) if {
	# Check Network type for zone-redundant configuration
	# VPC_CONSIST or VPC with specific settings may indicate zone-redundant
	network := helpers.get_property(resource, "Network", "NORMAL")

	# NORMAL network type typically uses local redundancy
	# VPC_CONSIST indicates zone-redundant storage
	network == "VPC_CONSIST"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OTS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Network"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
