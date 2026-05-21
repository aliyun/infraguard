package infraguard.rules.terraform.alb_server_group_multi_server

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "alb-server-group-multi-server",
	"severity": "high",
	"name": {
		"en": "ALB Server Group Has Multiple Servers",
		"zh": "ALB 服务器组包含至少两台服务器",
		"ja": "ALB サーバーグループに複数のサーバーがある",
		"de": "ALB-Servergruppe hat mehrere Server",
		"es": "El Grupo de Servidores ALB Tiene Múltiples Servidores",
		"fr": "Le Groupe de Serveurs ALB a Plusieurs Serveurs",
		"pt": "O Grupo de Servidores ALB Tem Múltiplos Servidores"
	},
	"description": {
		"en": "Ensures that ALB server groups contain at least two backend servers for high availability.",
		"zh": "确保 ALB 服务器组包含至少两台后端服务器以实现高可用性。",
		"ja": "ALB サーバーグループに高可用性のために少なくとも 2 つのバックエンドサーバーが含まれていることを確認します。",
		"de": "Stellt sicher, dass ALB-Servergruppen mindestens zwei Backend-Server für Hochverfügbarkeit enthalten.",
		"es": "Garantiza que los grupos de servidores ALB contengan al menos dos servidores backend para alta disponibilidad.",
		"fr": "Garantit que les groupes de serveurs ALB contiennent au moins deux serveurs backend pour une haute disponibilité.",
		"pt": "Garante que os grupos de servidores ALB contenham pelo menos dois servidores backend para alta disponibilidade."
	},
	"reason": {
		"en": "Server groups with only one server create a single point of failure.",
		"zh": "只有一台服务器的服务器组存在单点故障风险。",
		"ja": "サーバーが 1 つだけのサーバーグループは単一障害点を作成します。",
		"de": "Servergruppen mit nur einem Server schaffen einen Single Point of Failure.",
		"es": "Los grupos de servidores con solo un servidor crean un punto único de falla.",
		"fr": "Les groupes de serveurs avec un seul serveur créent un point de défaillance unique.",
		"pt": "Grupos de servidores com apenas um servidor criam um ponto único de falha."
	},
	"recommendation": {
		"en": "Add at least two backend servers to the server group using ALIYUN::ALB::BackendServerAttachment resources.",
		"zh": "使用 ALIYUN::ALB::BackendServerAttachment 资源，向服务器组添加至少两台后端服务器。",
		"ja": "ALIYUN::ALB::BackendServerAttachment リソースを使用して、サーバーグループに少なくとも 2 つのバックエンドサーバーを追加します。",
		"de": "Fügen Sie mindestens zwei Backend-Server zur Servergruppe hinzu, indem Sie ALIYUN::ALB::BackendServerAttachment-Ressourcen verwenden.",
		"es": "Agregue al menos dos servidores backend al grupo de servidores usando recursos ALIYUN::ALB::BackendServerAttachment.",
		"fr": "Ajoutez au moins deux serveurs backend au groupe de serveurs en utilisant les ressources ALIYUN::ALB::BackendServerAttachment.",
		"pt": "Adicione pelo menos dois servidores backend ao grupo de servidores usando recursos ALIYUN::ALB::BackendServerAttachment."
	},
	"resource_types": ["alicloud_alb_server_group", "alicloud_alb_server_group_server_attachment"],
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

server_count(server_group_id) := count({name |
	some name, attachment in tf.resources_by_type("alicloud_alb_server_group_server_attachment")
	attachment_belongs_to_group(attachment, server_group_id)
})

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_alb_server_group")
	is_applicable_type(resource)
	group_id := server_group_identifier(name, resource)
	server_count(group_id) < 2
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_alb_server_group.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
