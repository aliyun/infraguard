package infraguard.rules.aliyun.polardb_cluster_default_time_zone_not_system

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:polardb-cluster-default-time-zone-not-system",
	"name": {
		"en": "PolarDB Cluster Default Time Zone Not System",
		"zh": "PolarDB 集群默认时区参数值非 SYSTEM"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures PolarDB cluster default time zone is not set to SYSTEM.",
		"zh": "确保 PolarDB 集群的默认时区参数值不等于 SYSTEM。"
	},
	"reason": {
		"en": "Using explicit timezone ensures consistent time configuration.",
		"zh": "使用明确的时区确保时间配置一致。"
	},
	"recommendation": {
		"en": "Set an explicit timezone for the PolarDB cluster.",
		"zh": "为 PolarDB 集群设置明确的时区。"
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	params_json := db_cluster_params.Parameters
	is_string(params_json)
	params_json != ""
	params := json.unmarshal(params_json)
	default_time_zone := params.default_time_zone
	default_time_zone != null
	default_time_zone != "SYSTEM"
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	db_cluster_params == {}
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	db_cluster_params != {}
	db_cluster_params.Parameters == null
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	params_json := db_cluster_params.Parameters
	is_string(params_json)
	params_json == ""
}

is_compliant(resource) if {
	db_cluster_params := helpers.get_property(resource, "DBClusterParameters", {})
	params_json := db_cluster_params.Parameters
	is_string(params_json)
	params_json != ""
	params := json.unmarshal(params_json)
	params.default_time_zone == null
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DBClusterParameters", "Parameters", "default_time_zone"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
