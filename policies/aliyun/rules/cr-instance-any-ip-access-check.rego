package infraguard.rules.aliyun.cr_instance_any_ip_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:cr-instance-any-ip-access-check",
	"name": {
		"en": "CR Instance No Any IP Access",
		"zh": "容器镜像服务实例白名单检测"
	},
	"severity": "high",
	"description": {
		"en": "Ensures Container Registry instances do not have any IP (0.0.0.0/0) in their whitelist.",
		"zh": "确保容器镜像服务实例的白名单中不包含任意 IP（0.0.0.0/0）。"
	},
	"reason": {
		"en": "Allowing any IP (0.0.0.0/0) in the whitelist exposes the container registry to potential unauthorized access from any internet user.",
		"zh": "在白名单中允许任意 IP（0.0.0.0/0）会使容器镜像服务面临来自任何互联网用户的潜在未授权访问风险。"
	},
	"recommendation": {
		"en": "Remove 0.0.0.0/0 from the whitelist and specify specific IP ranges.",
		"zh": "从白名单中移除 0.0.0.0/0，并指定具体的 IP 范围。"
	},
	"resource_types": ["ALIYUN::CR::Instance"],
}

# Check if any ACL policy has 0.0.0.0/0 and is associated with a CR instance
has_any_ip_access(cr_instance_name) if {
	some acl_name, acl_resource in helpers.resources_by_type("ALIYUN::CR::InstanceEndpointAclPolicy")

	# Check if the entry is 0.0.0.0/0 (any IP)
	entry := helpers.get_property(acl_resource, "Entry", "")
	entry == "0.0.0.0/0"

	# Get the instance ID from the ACL policy (could be a GetAtt reference or string)
	instance_id_prop := helpers.get_property(acl_resource, "InstanceId", "")

	# Check if InstanceId is a GetAtt reference pointing to this CR instance
	helpers.is_get_att_referencing(instance_id_prop, cr_instance_name)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CR::Instance")
	has_any_ip_access(name)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
