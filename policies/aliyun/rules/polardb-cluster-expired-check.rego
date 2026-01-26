package infraguard.rules.aliyun.polardb_cluster_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "polardb-cluster-expired-check",
	"name": {
		"en": "PolarDB Cluster Expiration Check",
		"zh": "PolarDB 集群到期检查",
	},
	"severity": "high",
	"description": {
		"en": "Prepaid PolarDB clusters should have auto-renewal enabled.",
		"zh": "预付费 PolarDB 集群应开启自动续费，避免业务中断。",
	},
	"reason": {
		"en": "The prepaid PolarDB cluster does not have auto-renewal enabled.",
		"zh": "预付费 PolarDB 集群未开启自动续费。",
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid PolarDB cluster by setting RenewalStatus to AutoRenewal.",
		"zh": "通过将 RenewalStatus 设置为 AutoRenewal 为预付费 PolarDB 集群开启自动续费。",
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_prepaid(resource) if {
	helpers.get_property(resource, "PayType", "Postpaid") == "Prepaid"
}

is_auto_renew_enabled(resource) if {
	status := helpers.get_property(resource, "RenewalStatus", "Normal")
	status == "AutoRenewal"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RenewalStatus"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
