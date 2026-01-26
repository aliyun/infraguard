package infraguard.rules.aliyun.hbase_cluster_expired_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "hbase-cluster-expired-check",
	"name": {
		"en": "HBase Cluster Expiration Check",
		"zh": "HBase 集群到期检查",
	},
	"severity": "high",
	"description": {
		"en": "Prepaid HBase clusters should have auto-renewal enabled.",
		"zh": "预付费 HBase 集群应开启自动续费，避免业务中断。",
	},
	"reason": {
		"en": "The prepaid HBase cluster does not have auto-renewal enabled.",
		"zh": "预付费 HBase 集群未开启自动续费。",
	},
	"recommendation": {
		"en": "Enable auto-renewal for the prepaid HBase cluster by setting AutoRenewPeriod to a value greater than 0.",
		"zh": "通过将 AutoRenewPeriod 设置为大于 0 的值来开启自动续费。",
	},
	"resource_types": ["ALIYUN::HBase::Cluster"],
}

is_prepaid(resource) if {
	helpers.get_property(resource, "PayType", "Postpaid") == "Prepaid"
}

is_auto_renew_enabled(resource) if {
	period := helpers.get_property(resource, "AutoRenewPeriod", 0)
	period > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_prepaid(resource)
	not is_auto_renew_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AutoRenewPeriod"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
