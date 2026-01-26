package infraguard.rules.aliyun.ack_cluster_spec_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ack-cluster-spec-check",
	"name": {
		"en": "ACK Cluster Spec Check",
		"zh": "ACK 集群规格核查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures ACK clusters use approved specifications (e.g., ACK Pro).",
		"zh": "确保 ACK 集群使用批准的规格（如专业版 ACK Pro）。"
	},
	"reason": {
		"en": "ACK Pro version clusters provide better reliability and SLA guarantees for production workloads.",
		"zh": "ACK 专业版集群为生产工作负载提供更好的可靠性和 SLA 保障。"
	},
	"recommendation": {
		"en": "Upgrade the cluster to 'ack.pro.small' for production environments.",
		"zh": "对于生产环境，建议将集群规格升级为 'ack.pro.small'。"
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster"],
}

is_compliant(resource) if {
	spec := helpers.get_property(resource, "ClusterSpec", "")
	spec == "ack.pro.small"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CS::ManagedKubernetesCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ClusterSpec"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
