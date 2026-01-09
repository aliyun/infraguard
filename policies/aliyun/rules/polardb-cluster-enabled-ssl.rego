package infraguard.rules.aliyun.polardb_cluster_enabled_ssl

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:polardb-cluster-enabled-ssl",
	"name": {
		"en": "PolarDB Cluster SSL Enabled",
		"zh": "PolarDB 集群开启 SSL 加密"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures PolarDB clusters have SSL encryption enabled.",
		"zh": "确保 PolarDB 集群开启了 SSL 加密。"
	},
	"reason": {
		"en": "SSL encryption secures the communication between applications and the database cluster.",
		"zh": "SSL 加密保障了应用程序与数据库集群之间的通信安全。"
	},
	"recommendation": {
		"en": "Enable SSL for the PolarDB cluster.",
		"zh": "为 PolarDB 集群开启 SSL 加密。"
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"],
}

is_compliant(resource) if {
	ssl := helpers.get_property(resource, "SSLEnabled", "Disable")
	ssl == "Enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SSLEnabled"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
