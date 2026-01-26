package infraguard.rules.aliyun.ack_cluster_public_endpoint_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ack-cluster-public-endpoint-check",
	"name": {
		"en": "ACK Cluster Public Endpoint Check",
		"zh": "ACK 集群未设置公网连接端点",
	},
	"severity": "high",
	"description": {
		"en": "ACK clusters should not have a public endpoint set, or the associated SLB listener should have ACL enabled.",
		"zh": "ACK 集群未设置公网连接端点，或关联的 SLB 的监听开启 acl 访问控制，视为合规。",
	},
	"reason": {
		"en": "The ACK cluster has a public endpoint enabled, which may expose the API server to the internet.",
		"zh": "ACK 集群开启了公网连接端点，可能将 API Server 暴露给互联网。",
	},
	"recommendation": {
		"en": "Disable the public endpoint for the ACK cluster by setting 'EndpointPublicAccess' to false.",
		"zh": "通过将'EndpointPublicAccess'设置为 false 来禁用 ACK 集群的公网连接端点。",
	},
	"resource_types": [
		"ALIYUN::CS::ManagedKubernetesCluster",
		"ALIYUN::CS::ASKCluster",
	],
}

# Check for ManagedKubernetesCluster
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CS::ManagedKubernetesCluster")
	helpers.get_property(resource, "EndpointPublicAccess", false) == true
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EndpointPublicAccess"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

# Check for ASKCluster
# Default for ASKCluster EndpointPublicAccess is true
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CS::ASKCluster")
	is_ask_public_access_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EndpointPublicAccess"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

is_ask_public_access_enabled(resource) if {
	# If explicitly true
	helpers.get_property(resource, "EndpointPublicAccess", false) == true
}

is_ask_public_access_enabled(resource) if {
	# If missing, default is true
	not helpers.has_property(resource, "EndpointPublicAccess")
}
