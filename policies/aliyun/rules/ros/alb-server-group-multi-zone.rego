package infraguard.rules.aliyun.alb_server_group_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "alb-server-group-multi-zone",
	"severity": "medium",
	"name": {
		"en": "ALB Server Group Multi-Zone Distribution",
		"zh": "ALB 负载均衡服务器组添加多个可用区资源",
		"ja": "ALB サーバーグループマルチゾーン分散",
		"de": "ALB-Servergruppe Multi-Zone-Verteilung",
		"es": "Distribución Multi-Zona del Grupo de Servidores ALB",
		"fr": "Distribution Multi-Zone du Groupe de Serveurs ALB",
		"pt": "Distribuição Multi-Zona do Grupo de Servidores ALB"
	},
	"description": {
		"en": "ALB server groups should have backend servers distributed across multiple availability zones for high availability. This rule does not apply to server groups with no attached servers, or to IP/Function Compute type server groups.",
		"zh": "ALB 负载均衡的服务器组挂载资源分布在多个可用区，视为合规。ALB 服务器组无挂载任何资源时不适用本规则，视为不适用。IP 或者函数计算类型的服务器组视为不适用。",
		"ja": "ALB サーバーグループは、高可用性のために複数の可用性ゾーンに分散されたバックエンドサーバーを持つ必要があります。このルールは、アタッチされたサーバーがないサーバーグループ、または IP/Function Compute タイプのサーバーグループには適用されません。",
		"de": "ALB-Servergruppen sollten Backend-Server über mehrere Verfügbarkeitszonen verteilt haben, um Hochverfügbarkeit zu gewährleisten. Diese Regel gilt nicht für Servergruppen ohne angehängte Server oder für IP/Function Compute-Typ-Servergruppen.",
		"es": "Los grupos de servidores ALB deben tener servidores backend distribuidos en múltiples zonas de disponibilidad para alta disponibilidad. Esta regla no se aplica a grupos de servidores sin servidores adjuntos, ni a grupos de servidores de tipo IP/Function Compute.",
		"fr": "Les groupes de serveurs ALB doivent avoir des serveurs backend distribués sur plusieurs zones de disponibilité pour une haute disponibilité. Cette règle ne s'applique pas aux groupes de serveurs sans serveurs attachés, ni aux groupes de serveurs de type IP/Function Compute.",
		"pt": "Os grupos de servidores ALB devem ter servidores backend distribuídos em múltiplas zonas de disponibilidade para alta disponibilidade. Esta regra não se aplica a grupos de servidores sem servidores anexados, nem a grupos de servidores do tipo IP/Function Compute."
	},
	"reason": {
		"en": "The ALB server group has backend servers in only one availability zone, creating a single point of failure.",
		"zh": "ALB 服务器组的后端服务器仅分布在一个可用区，存在单点故障风险。",
		"ja": "ALB サーバーグループのバックエンドサーバーが 1 つの可用性ゾーンにのみ存在し、単一障害点が発生しています。",
		"de": "Die ALB-Servergruppe hat Backend-Server nur in einer Verfügbarkeitszone, was einen Single Point of Failure schafft.",
		"es": "El grupo de servidores ALB tiene servidores backend en solo una zona de disponibilidad, creando un punto único de falla.",
		"fr": "Le groupe de serveurs ALB a des serveurs backend dans une seule zone de disponibilité, créant un point de défaillance unique.",
		"pt": "O grupo de servidores ALB tem servidores backend em apenas uma zona de disponibilidade, criando um ponto único de falha."
	},
	"recommendation": {
		"en": "Add backend servers from at least two different availability zones to the server group using ALIYUN::ALB::BackendServerAttachment resources.",
		"zh": "使用 ALIYUN::ALB::BackendServerAttachment 资源，向服务器组添加来自至少两个不同可用区的后端服务器。",
		"ja": "ALIYUN::ALB::BackendServerAttachment リソースを使用して、少なくとも 2 つの異なる可用性ゾーンからバックエンドサーバーをサーバーグループに追加します。",
		"de": "Fügen Sie Backend-Server aus mindestens zwei verschiedenen Verfügbarkeitszonen zur Servergruppe hinzu, indem Sie ALIYUN::ALB::BackendServerAttachment-Ressourcen verwenden.",
		"es": "Agregue servidores backend de al menos dos zonas de disponibilidad diferentes al grupo de servidores usando recursos ALIYUN::ALB::BackendServerAttachment.",
		"fr": "Ajoutez des serveurs backend d'au moins deux zones de disponibilité différentes au groupe de serveurs en utilisant les ressources ALIYUN::ALB::BackendServerAttachment.",
		"pt": "Adicione servidores backend de pelo menos duas zonas de disponibilidade diferentes ao grupo de servidores usando recursos ALIYUN::ALB::BackendServerAttachment."
	},
	"resource_types": ["ALIYUN::ALB::ServerGroup"]
}

# Check if server group type is applicable (not IP or Fc)
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
		some _, attachment in helpers.resources_by_type("ALIYUN::ALB::BackendServerAttachment")
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
	some _, attachment in helpers.resources_by_type("ALIYUN::ALB::BackendServerAttachment")
	attachment_belongs_to_group(attachment, server_group_id)
}

# Check if servers are distributed across multiple zones
is_multi_zone_distributed(server_group_id) if {
	zones := zones_for_server_group(server_group_id)
	count(zones) >= 2
}

# Deny rule: ALB server groups must have servers in multiple zones
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::ServerGroup")

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
