package infraguard.rules.aliyun.alb_server_group_multi_server

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "alb-server-group-multi-server",
	"name": {
		"en": "ALB Server Group Has Multiple Servers",
		"zh": "ALB 服务器组包含至少两台服务器",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ALB server groups contain at least two backend servers for high availability.",
		"zh": "确保 ALB 服务器组包含至少两台后端服务器以实现高可用性。",
	},
	"reason": {
		"en": "Server groups with only one server create a single point of failure.",
		"zh": "只有一台服务器的服务器组存在单点故障风险。",
	},
	"recommendation": {
		"en": "Add at least two backend servers to the server group using ALIYUN::ALB::BackendServerAttachment resources.",
		"zh": "使用 ALIYUN::ALB::BackendServerAttachment 资源，向服务器组添加至少两台后端服务器。",
	},
	"resource_types": ["ALIYUN::ALB::ServerGroup"],
}

# Check if server group type is Instance (not IP or Function Compute)
is_applicable_type(resource) if {
	server_group_type := helpers.get_property(resource, "ServerGroupType", "Instance")
	server_group_type == "Instance"
}

# Get server group ID from reference or direct value
get_server_group_id(value) := value if {
	is_string(value)
}

get_server_group_id(value) := ref_val if {
	is_object(value)
	ref_val := value.Ref
}

# Check if attachment belongs to this server group
attachment_belongs_to_group(attachment, server_group_id) if {
	group_id := get_server_group_id(attachment.Properties.ServerGroupId)
	group_id == server_group_id
}

# Count servers attached to a server group
get_server_count(server_group_id) := server_count if {
	attachments := [attachment |
		some _, attachment in helpers.resources_by_type("ALIYUN::ALB::BackendServerAttachment")
		attachment_belongs_to_group(attachment, server_group_id)
	]

	servers := [server |
		some attachment in attachments
		some server in attachment.Properties.Servers
	]

	server_count := count(servers)
}

# Check if server group has at least 2 servers
has_min_servers(server_group_id) if {
	server_count := get_server_count(server_group_id)
	server_count >= 2
}

is_compliant(name, resource) if {
	is_applicable_type(resource)
	has_min_servers(name)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::ServerGroup")

	# Only check Instance type server groups
	is_applicable_type(resource)

	not is_compliant(name, resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
