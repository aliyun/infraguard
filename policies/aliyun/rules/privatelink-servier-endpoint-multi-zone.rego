package infraguard.rules.aliyun.privatelink_servier_endpoint_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "privatelink-servier-endpoint-multi-zone",
	"name": {
		"en": "PrivateLink Service Endpoint Multi-Zone Deployment",
		"zh": "PrivateLink 服务终端节点多可用区部署",
		"ja": "PrivateLink サービスエンドポイントマルチゾーン展開",
		"de": "PrivateLink Service Endpoint Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Punto Final de Servicio PrivateLink",
		"fr": "Déploiement Multi-Zone du Point de Terminaison de Service PrivateLink",
		"pt": "Implantações Multi-Zona do Ponto de Extremidade de Serviço PrivateLink",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that PrivateLink service endpoints are deployed across multiple zones for high availability.",
		"zh": "确保 PrivateLink 服务终端节点部署在多个可用区以实现高可用性。",
		"ja": "PrivateLink サービスエンドポイントが高可用性のために複数のゾーンに展開されていることを確認します。",
		"de": "Stellt sicher, dass PrivateLink-Service-Endpunkte über mehrere Zonen hinweg für Hochverfügbarkeit bereitgestellt werden.",
		"es": "Garantiza que los puntos finales de servicio PrivateLink estén desplegados en múltiples zonas para alta disponibilidad.",
		"fr": "Garantit que les points de terminaison de service PrivateLink sont déployés sur plusieurs zones pour une haute disponibilité.",
		"pt": "Garante que os pontos de extremidade de serviço PrivateLink estejam implantados em múltiplas zonas para alta disponibilidade.",
	},
	"reason": {
		"en": "Multi-zone deployment ensures connectivity to the service even during an availability zone failure.",
		"zh": "多可用区部署可确保即使在可用区故障期间也能连接到服务。",
		"ja": "マルチゾーン展開により、可用性ゾーン障害中でもサービスへの接続が確保されます。",
		"de": "Multi-Zone-Bereitstellung gewährleistet die Verbindung zum Service auch während eines Verfügbarkeitszonenausfalls.",
		"es": "El despliegue multi-zona garantiza la conectividad al servicio incluso durante una falla de zona de disponibilidad.",
		"fr": "Le déploiement multi-zone garantit la connectivité au service même pendant une panne de zone de disponibilité.",
		"pt": "A implantação multi-zona garante conectividade ao serviço mesmo durante uma falha de zona de disponibilidade.",
	},
	"recommendation": {
		"en": "Deploy PrivateLink service endpoints in at least two different availability zones.",
		"zh": "在至少两个不同的可用区中部署 PrivateLink 服务终端节点。",
		"ja": "少なくとも 2 つの異なる可用性ゾーンに PrivateLink サービスエンドポイントを展開します。",
		"de": "Stellen Sie PrivateLink-Service-Endpunkte in mindestens zwei verschiedenen Verfügbarkeitszonen bereit.",
		"es": "Despliegue puntos finales de servicio PrivateLink en al menos dos zonas de disponibilidad diferentes.",
		"fr": "Déployez les points de terminaison de service PrivateLink dans au moins deux zones de disponibilité différentes.",
		"pt": "Implante pontos de extremidade de serviço PrivateLink em pelo menos duas zonas de disponibilidade diferentes.",
	},
	"resource_types": ["ALIYUN::PrivateLink::VpcEndpoint"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::PrivateLink::VpcEndpoint")
	zones := helpers.get_property(resource, "Zone", [])
	count(zones) < 2
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Zone"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
