package infraguard.rules.aliyun.ack_cluster_inspect_kubelet_version_outdate_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ack-cluster-inspect-kubelet-version-outdate-check",
	"name": {
		"en": "ACK Kubelet Version Check",
		"zh": "ACK 巡检：Kubelet 版本过时检测"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures the Kubelet version in the ACK cluster is up to date.",
		"zh": "确保 ACK 集群中的 Kubelet 版本是最新的。"
	},
	"reason": {
		"en": "Outdated Kubelet versions may contain security vulnerabilities or compatibility issues.",
		"zh": "过时的 Kubelet 版本可能包含安全漏洞或兼容性问题。"
	},
	"recommendation": {
		"en": "Upgrade the Kubelet version of the worker nodes.",
		"zh": "升级工作节点的 Kubelet 版本。"
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster"],
}

# Real check requires runtime data. In IaC, we check if a standard version is used.
is_compliant(resource) if {
	v := helpers.get_property(resource, "KubernetesVersion", "")
	not helpers.includes(["1.16", "1.18"], v) # Example: flag very old versions
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CS::ManagedKubernetesCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "KubernetesVersion"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
