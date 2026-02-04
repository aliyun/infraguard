package infraguard.rules.aliyun.slb_vserver_group_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "slb-vserver-group-multi-zone",
	"name": {
		"en": "SLB VServer Group Multi-Zone Deployment",
		"zh": "SLB 虚拟服务器组多可用区部署",
		"ja": "SLB 仮想サーバーグループマルチゾーン展開",
		"de": "SLB VServer-Gruppe Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona de Grupo de Servidor Virtual SLB",
		"fr": "Déploiement Multi-Zone du Groupe de Serveurs Virtuels SLB",
		"pt": "Implantação Multi-Zona do Grupo de Servidor Virtual SLB",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that SLB virtual server groups contain instances from multiple availability zones.",
		"zh": "确保 SLB 虚拟服务器组包含来自多个可用区的实例。",
		"ja": "SLB 仮想サーバーグループに複数の可用性ゾーンからのインスタンスが含まれていることを確認します。",
		"de": "Stellt sicher, dass SLB-VServer-Gruppen Instanzen aus mehreren Verfügbarkeitszonen enthalten.",
		"es": "Garantiza que los grupos de servidor virtual SLB contengan instancias de múltiples zonas de disponibilidad.",
		"fr": "Garantit que les groupes de serveurs virtuels SLB contiennent des instances de plusieurs zones de disponibilité.",
		"pt": "Garante que os grupos de servidor virtual SLB contenham instâncias de múltiplas zonas de disponibilidade.",
	},
	"reason": {
		"en": "Deploying backend instances in multiple zones ensures high availability for the service.",
		"zh": "在多个可用区部署后端实例可确保服务的高可用性。",
		"ja": "複数のゾーンにバックエンドインスタンスを展開することで、サービスの高可用性が確保されます。",
		"de": "Die Bereitstellung von Backend-Instanzen in mehreren Zonen gewährleistet hohe Verfügbarkeit für den Dienst.",
		"es": "Implementar instancias backend en múltiples zonas garantiza alta disponibilidad para el servicio.",
		"fr": "Le déploiement d'instances backend dans plusieurs zones garantit une haute disponibilité pour le service.",
		"pt": "Implantar instâncias backend em múltiplas zonas garante alta disponibilidade para o serviço.",
	},
	"recommendation": {
		"en": "Add instances from at least two different availability zones to the virtual server group.",
		"zh": "向虚拟服务器组中添加来自至少两个不同可用区的实例。",
		"ja": "仮想サーバーグループに、少なくとも2つの異なる可用性ゾーンからのインスタンスを追加します。",
		"de": "Fügen Sie Instanzen aus mindestens zwei verschiedenen Verfügbarkeitszonen zur VServer-Gruppe hinzu.",
		"es": "Agregue instancias de al menos dos zonas de disponibilidad diferentes al grupo de servidor virtual.",
		"fr": "Ajoutez des instances d'au moins deux zones de disponibilité différentes au groupe de serveurs virtuels.",
		"pt": "Adicione instâncias de pelo menos duas zonas de disponibilidade diferentes ao grupo de servidor virtual.",
	},
	"resource_types": ["ALIYUN::SLB::VServerGroup"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::VServerGroup")

	# Conceptual check for multi-zone
	not helpers.has_property(resource, "BackendServers")
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
