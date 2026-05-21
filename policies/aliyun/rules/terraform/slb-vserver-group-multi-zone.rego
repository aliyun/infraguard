package infraguard.rules.terraform.slb_vserver_group_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-vserver-group-multi-zone",
	"severity": "medium",
	"name": {
		"en": "SLB VServer Group Multi-Zone Deployment",
		"zh": "SLB 虚拟服务器组多可用区部署",
		"ja": "SLB 仮想サーバーグループマルチゾーン展開",
		"de": "SLB VServer-Gruppe Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona de Grupo de Servidor Virtual SLB",
		"fr": "Déploiement Multi-Zone du Groupe de Serveurs Virtuels SLB",
		"pt": "Implantação Multi-Zona do Grupo de Servidor Virtual SLB"
	},
	"description": {
		"en": "Ensures that SLB virtual server groups contain instances from multiple availability zones.",
		"zh": "确保 SLB 虚拟服务器组包含来自多个可用区的实例。",
		"ja": "SLB 仮想サーバーグループに複数の可用性ゾーンからのインスタンスが含まれていることを確認します。",
		"de": "Stellt sicher, dass SLB-VServer-Gruppen Instanzen aus mehreren Verfügbarkeitszonen enthalten.",
		"es": "Garantiza que los grupos de servidor virtual SLB contengan instancias de múltiples zonas de disponibilidad.",
		"fr": "Garantit que les groupes de serveurs virtuels SLB contiennent des instances de plusieurs zones de disponibilité.",
		"pt": "Garante que os grupos de servidor virtual SLB contenham instâncias de múltiplas zonas de disponibilidade."
	},
	"reason": {
		"en": "Deploying backend instances in multiple zones ensures high availability for the service.",
		"zh": "在多个可用区部署后端实例可确保服务的高可用性。",
		"ja": "複数のゾーンにバックエンドインスタンスを展開することで、サービスの高可用性が確保されます。",
		"de": "Die Bereitstellung von Backend-Instanzen in mehreren Zonen gewährleistet hohe Verfügbarkeit für den Dienst.",
		"es": "Implementar instancias backend en múltiples zonas garantiza alta disponibilidad para el servicio.",
		"fr": "Le déploiement d'instances backend dans plusieurs zones garantit une haute disponibilité pour le service.",
		"pt": "Implantar instâncias backend em múltiplas zonas garante alta disponibilidade para o serviço."
	},
	"recommendation": {
		"en": "Add at least 2 servers entries to the alicloud_slb_server_group resource for multi-zone deployment.",
		"zh": "向 alicloud_slb_server_group 资源添加至少 2 个 servers 条目以实现多可用区部署。",
		"ja": "マルチゾーン展開のために alicloud_slb_server_group リソースに少なくとも 2 つの servers エントリを追加します。",
		"de": "Fügen Sie mindestens 2 servers-Einträge zur alicloud_slb_server_group-Ressource für Multi-Zonen-Bereitstellung hinzu.",
		"es": "Agregue al menos 2 entradas servers al recurso alicloud_slb_server_group para implementación multi-zona.",
		"fr": "Ajoutez au moins 2 entrées servers à la ressource alicloud_slb_server_group pour un déploiement multi-zone.",
		"pt": "Adicione pelo menos 2 entradas servers ao recurso alicloud_slb_server_group para implantação multi-zona."
	},
	"resource_types": ["alicloud_slb_server_group"],
	"iac_type": "terraform"
}

as_array(value) := value if is_array(value)

else := [value] if is_object(value)

else := []

server_list(resource) := as_array(tf.get_attribute(resource, "servers", []))

has_multi_servers(resource) if {
	count(server_list(resource)) >= 2
}

has_servers(resource) if {
	count(server_list(resource)) > 0
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_server_group")
	has_servers(resource)
	not has_multi_servers(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_server_group.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
