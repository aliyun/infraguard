package infraguard.rules.aliyun.lindorm_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "lindorm-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "Lindorm Instance Multi-Zone Deployment",
		"zh": "使用多可用区的云原生多模数据库 Lindorm 实例",
		"ja": "Lindorm インスタンスマルチゾーン展開",
		"de": "Lindorm-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia Lindorm",
		"fr": "Déploiement Multi-Zone d'Instance Lindorm",
		"pt": "Implantações Multi-Zona de Instância Lindorm"
	},
	"description": {
		"en": "Lindorm instances should be configured for multi-zone deployment with at least 4 LindormTable nodes for high availability.",
		"zh": "使用多可用区的云原生多模数据库 Lindorm 实例，视为合规。",
		"ja": "Lindorm インスタンスは、高可用性のために少なくとも 4 つの LindormTable ノードでマルチゾーン展開用に設定する必要があります。",
		"de": "Lindorm-Instanzen sollten für Multi-Zone-Bereitstellung mit mindestens 4 LindormTable-Knoten für Hochverfügbarkeit konfiguriert werden.",
		"es": "Las instancias Lindorm deben configurarse para despliegue multi-zona con al menos 4 nodos LindormTable para alta disponibilidad.",
		"fr": "Les instances Lindorm doivent être configurées pour un déploiement multi-zone avec au moins 4 nœuds LindormTable pour une haute disponibilité.",
		"pt": "As instâncias Lindorm devem ser configuradas para implantação multi-zona com pelo menos 4 nós LindormTable para alta disponibilidade."
	},
	"reason": {
		"en": "The Lindorm instance does not meet the multi-zone deployment requirements (LindormNum < 4).",
		"zh": "Lindorm 实例不满足多可用区部署要求（LindormNum < 4）。",
		"ja": "Lindorm インスタンスがマルチゾーン展開要件（LindormNum < 4）を満たしていません。",
		"de": "Die Lindorm-Instanz erfüllt nicht die Multi-Zone-Bereitstellungsanforderungen (LindormNum < 4).",
		"es": "La instancia Lindorm no cumple con los requisitos de despliegue multi-zona (LindormNum < 4).",
		"fr": "L'instance Lindorm ne répond pas aux exigences de déploiement multi-zone (LindormNum < 4).",
		"pt": "A instância Lindorm não atende aos requisitos de implantação multi-zona (LindormNum < 4)."
	},
	"recommendation": {
		"en": "Configure at least 4 LindormTable nodes by setting LindormNum to 4 or more to enable multi-zone deployment.",
		"zh": "通过将 LindormNum 设置为 4 或更多来配置至少 4 个 LindormTable 节点，以启用多可用区部署。",
		"ja": "LindormNum を 4 以上に設定して、少なくとも 4 つの LindormTable ノードを設定し、マルチゾーン展開を有効にします。",
		"de": "Konfigurieren Sie mindestens 4 LindormTable-Knoten, indem Sie LindormNum auf 4 oder mehr setzen, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure al menos 4 nodos LindormTable estableciendo LindormNum en 4 o más para habilitar el despliegue multi-zona.",
		"fr": "Configurez au moins 4 nœuds LindormTable en définissant LindormNum sur 4 ou plus pour activer le déploiement multi-zone.",
		"pt": "Configure pelo menos 4 nós LindormTable definindo LindormNum como 4 ou mais para habilitar a implantação multi-zona."
	},
	"resource_types": ["ALIYUN::Lindorm::Instance"]
}

# Check if instance is multi-zone (requires LindormNum >= 4)
is_multi_zone(resource) if {
	helpers.has_property(resource, "LindormNum")
	lindorm_num := resource.Properties.LindormNum
	lindorm_num >= 4
}

# Deny rule: Lindorm instances should be multi-zone
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::Lindorm::Instance")
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LindormNum"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
