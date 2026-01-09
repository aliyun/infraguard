package infraguard.rules.aliyun.ack_cluster_log_plugin_installed

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:ack-cluster-log-plugin-installed",
	"name": {
		"en": "ACK Cluster Log Plugin Installed",
		"zh": "ACK 集群安装日志插件"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures the log-service addon is installed in the ACK cluster.",
		"zh": "确保 ACK 集群中安装了 log-service 组件。"
	},
	"reason": {
		"en": "Log collection is essential for monitoring and troubleshooting containerized applications.",
		"zh": "日志采集对于监控和排查容器化应用的故障至关重要。"
	},
	"recommendation": {
		"en": "Install the 'log-service' addon in the ACK cluster settings.",
		"zh": "在 ACK 集群设置中安装 'log-service' 组件。"
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster"],
}

is_compliant(resource) if {
	addons := helpers.get_property(resource, "Addons", [])
	some addon in addons
	addon.Name == "log-service"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CS::ManagedKubernetesCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Addons"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
