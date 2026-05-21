package infraguard.rules.terraform.nlb_server_group_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "nlb-server-group-multi-zone",
	"severity": "medium",
	"name": {
		"en": "NLB Server Group Multi-Zone Distribution",
		"zh": "NLB 负载均衡服务器组添加多个可用区资源",
		"ja": "NLB サーバーグループのマルチゾーン分散",
		"de": "NLB-Server-Gruppe Multi-Zone-Verteilung",
		"es": "Distribución Multi-Zona del Grupo de Servidores NLB",
		"fr": "Distribution Multi-Zone du Groupe de Serveurs NLB",
		"pt": "Distribuição Multi-Zona do Grupo de Servidores NLB"
	},
	"description": {
		"en": "NLB server groups should have backend servers distributed across multiple availability zones.",
		"zh": "网络负载均衡的服务器组中资源分布在多个可用区，视为合规。",
		"ja": "NLB サーバーグループは高可用性のために、バックエンドサーバーを複数の可用性ゾーンに分散させる必要があります。このルールは、サーバーが接続されていないサーバーグループ、または IP タイプのサーバーグループには適用されません。",
		"de": "NLB-Server-Gruppen sollten Backend-Server für hohe Verfügbarkeit über mehrere Verfügbarkeitszonen verteilt haben. Diese Regel gilt nicht für Server-Gruppen ohne angehängte Server oder für IP-Typ-Server-Gruppen.",
		"es": "Los grupos de servidores NLB deben tener servidores backend distribuidos en múltiples zonas de disponibilidad para alta disponibilidad. Esta regla no se aplica a grupos de servidores sin servidores adjuntos, ni a grupos de servidores de tipo IP.",
		"fr": "Les groupes de serveurs NLB doivent avoir des serveurs backend distribués sur plusieurs zones de disponibilité pour une haute disponibilité. Cette règle ne s'applique pas aux groupes de serveurs sans serveurs attachés, ni aux groupes de serveurs de type IP.",
		"pt": "Os grupos de servidores NLB devem ter servidores backend distribuídos em múltiplas zonas de disponibilidade para alta disponibilidade. Esta regra não se aplica a grupos de servidores sem servidores anexados ou a grupos de servidores do tipo IP."
	},
	"reason": {
		"en": "The NLB server group has backend servers in only one availability zone.",
		"zh": "NLB 服务器组的后端服务器仅分布在一个可用区，存在单点故障风险。",
		"ja": "NLB サーバーグループのバックエンドサーバーが 1 つの可用性ゾーンにのみ存在し、単一障害点が作成されています。",
		"de": "Die NLB-Server-Gruppe hat Backend-Server nur in einer Verfügbarkeitszone, was einen Single Point of Failure schafft.",
		"es": "El grupo de servidores NLB tiene servidores backend en solo una zona de disponibilidad, creando un punto único de falla.",
		"fr": "Le groupe de serveurs NLB a des serveurs backend dans une seule zone de disponibilité, créant un point de défaillance unique.",
		"pt": "O grupo de servidores NLB tem servidores backend em apenas uma zona de disponibilidade, criando um ponto único de falha."
	},
	"recommendation": {
		"en": "Add backend servers from at least two different availability zones.",
		"zh": "向服务器组添加来自至少两个不同可用区的后端服务器。",
		"ja": "ALIYUN::NLB::BackendServerAttachment リソースを使用して、少なくとも 2 つの異なる可用性ゾーンからバックエンドサーバーをサーバーグループに追加します。",
		"de": "Fügen Sie Backend-Server aus mindestens zwei verschiedenen Verfügbarkeitszonen zur Server-Gruppe hinzu, indem Sie ALIYUN::NLB::BackendServerAttachment-Ressourcen verwenden.",
		"es": "Agregue servidores backend de al menos dos zonas de disponibilidad diferentes al grupo de servidores usando recursos ALIYUN::NLB::BackendServerAttachment.",
		"fr": "Ajoutez des serveurs backend d'au moins deux zones de disponibilité différentes au groupe de serveurs en utilisant les ressources ALIYUN::NLB::BackendServerAttachment.",
		"pt": "Adicione servidores backend de pelo menos duas zonas de disponibilidade diferentes ao grupo de servidores usando recursos ALIYUN::NLB::BackendServerAttachment."
	},
	"resource_types": ["alicloud_instance", "alicloud_nlb_server_group", "alicloud_nlb_server_group_server_attachment"],
	"iac_type": "terraform"
}

server_group_identifier(name, resource) := id if {
	id := tf.get_attribute(resource, "server_group_id", "")
	id != ""
	not tf.is_unknown(id)
} else := name

is_applicable_type(resource) if {
	server_group_type := tf.get_attribute(resource, "server_group_type", "Instance")
	server_group_type == "Instance"
}

attachment_belongs_to_group(attachment, server_group_id) if {
	group_id := tf.get_attribute(attachment, "server_group_id", "")
	group_id == server_group_id
}

server_id_for_attachment(attachment) := server_id if {
	server_id := tf.get_attribute(attachment, "server_id", "")
	server_id != ""
	not tf.is_unknown(server_id)
}

zone_for_server(server_id) := zone if {
	some name, instance in tf.resources_by_type("alicloud_instance")
	name == server_id
	zone := tf.get_attribute(instance, "zone_id", "")
	zone != ""
	not tf.is_unknown(zone)
}

zones_for_server_group(server_group_id) := zones if {
	zones := {zone |
		some _, attachment in tf.resources_by_type("alicloud_nlb_server_group_server_attachment")
		attachment_belongs_to_group(attachment, server_group_id)
		server_id := server_id_for_attachment(attachment)
		zone := zone_for_server(server_id)
	}
}

has_attachments(server_group_id) if {
	some _, attachment in tf.resources_by_type("alicloud_nlb_server_group_server_attachment")
	attachment_belongs_to_group(attachment, server_group_id)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_nlb_server_group")
	is_applicable_type(resource)
	group_id := server_group_identifier(name, resource)
	has_attachments(group_id)
	count(zones_for_server_group(group_id)) < 2
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_nlb_server_group.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
