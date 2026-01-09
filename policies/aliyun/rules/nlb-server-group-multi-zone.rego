package infraguard.rules.aliyun.nlb_server_group_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:nlb-server-group-multi-zone",
	"name": {
		"en": "NLB Server Group Multi-Zone Distribution",
		"zh": "NLB 负载均衡服务器组添加多个可用区资源",
	},
	"severity": "medium",
	"description": {
		"en": "NLB server groups should have backend servers distributed across multiple availability zones for high availability. This rule does not apply to server groups with no attached servers, or to IP type server groups.",
		"zh": "网络负载均衡的服务器组中资源分布在多个可用区，视为合规。服务器组中无资源或者资源类型为 IP 时，视为不适用。",
	},
	"reason": {
		"en": "The NLB server group has backend servers in only one availability zone, creating a single point of failure.",
		"zh": "NLB 服务器组的后端服务器仅分布在一个可用区，存在单点故障风险。",
	},
	"recommendation": {
		"en": "Add backend servers from at least two different availability zones to the server group using ALIYUN::NLB::BackendServerAttachment resources.",
		"zh": "使用 ALIYUN::NLB::BackendServerAttachment 资源，向服务器组添加来自至少两个不同可用区的后端服务器。",
	},
	"resource_types": ["ALIYUN::NLB::ServerGroup"],
}

# Check if server group type is applicable (Instance)
is_applicable_type(resource) if {
	server_group_type := helpers.get_property(resource, "ServerGroupType", "Instance")
	server_group_type == "Instance"
}

# Get server group ID from reference or direct value
get_server_group_id(value) := value if {
	is_string(value)
}

get_server_group_id(value) := value.Ref if {
	is_object(value)
	value.Ref
}

# Get server ID from reference or direct value
get_server_id(value) := value if {
	is_string(value)
}

get_server_id(value) := value.Ref if {
	is_object(value)
	value.Ref
}

# Check if attachment belongs to this server group
attachment_belongs_to_group(attachment, server_group_id) if {
	group_id := get_server_group_id(attachment.Properties.ServerGroupId)
	group_id == server_group_id
}

# Get all zones from backend servers for a server group
zones_for_server_group(server_group_id) := zones if {
	# Find all attachments for this server group
	attachments := [attachment |
		some _, attachment in helpers.resources_by_type("ALIYUN::NLB::BackendServerAttachment")
		attachment_belongs_to_group(attachment, server_group_id)
	]

	# Get all zones from servers in these attachments
	zones := {zone |
		some attachment in attachments
		some server in attachment.Properties.Servers
		server_id := get_server_id(server.ServerId)

		# Look up the server resource
		some name, resource in input.Resources
		name == server_id
		resource.Type in {"ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"}
		zone := resource.Properties.ZoneId
	}
}

# Check if server group has attachments
has_attachments(server_group_id) if {
	some _, attachment in helpers.resources_by_type("ALIYUN::NLB::BackendServerAttachment")
	attachment_belongs_to_group(attachment, server_group_id)
}

# Check if servers are distributed across multiple zones
is_multi_zone_distributed(server_group_id) if {
	zones := zones_for_server_group(server_group_id)
	count(zones) >= 2
}

# Deny rule: NLB server groups must have servers in multiple zones
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NLB::ServerGroup")

	# Only check Instance type server groups
	is_applicable_type(resource)

	# Only check if there are attachments
	has_attachments(name)

	# Check if not multi-zone
	not is_multi_zone_distributed(name)

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
