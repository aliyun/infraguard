package infraguard.rules.aliyun.polardb_x2_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "polardb-x2-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "PolarDB-X 2.0 Instance Multi-Zone Deployment",
		"zh": "PolarDB-X 2.0 实例多可用区部署",
		"ja": "PolarDB-X 2.0 インスタンスのマルチゾーン展開",
		"de": "PolarDB-X 2.0-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia PolarDB-X 2.0",
		"fr": "Déploiement Multi-Zone de l'Instance PolarDB-X 2.0",
		"pt": "Implantação Multi-Zona da Instância PolarDB-X 2.0"
	},
	"description": {
		"en": "PolarDB-X 2.0 instances should be deployed across 3 availability zones.",
		"zh": "PolarDB-X 2.0 实例应部署在 3 个可用区。",
		"ja": "PolarDB-X 2.0 インスタンスは 3 つの可用性ゾーンにまたがって展開する必要があります。",
		"de": "PolarDB-X 2.0-Instanzen sollten über 3 Verfügbarkeitszonen hinweg bereitgestellt werden.",
		"es": "Las instancias PolarDB-X 2.0 deben desplegarse en 3 zonas de disponibilidad.",
		"fr": "Les instances PolarDB-X 2.0 doivent être déployées sur 3 zones de disponibilité.",
		"pt": "As instâncias PolarDB-X 2.0 devem ser implantadas em 3 zonas de disponibilidade."
	},
	"reason": {
		"en": "The PolarDB-X 2.0 instance is configured with single-zone topology.",
		"zh": "PolarDB-X 2.0 实例配置为单可用区拓扑。",
		"ja": "PolarDB-X 2.0 インスタンスが単一ゾーントポロジで設定されています。",
		"de": "Die PolarDB-X 2.0-Instanz ist mit Einzelzonen-Topologie konfiguriert.",
		"es": "La instancia PolarDB-X 2.0 está configurada con topología de zona única.",
		"fr": "L'instance PolarDB-X 2.0 est configurée avec une topologie à zone unique.",
		"pt": "A instância PolarDB-X 2.0 está configurada com topologia de zona única."
	},
	"recommendation": {
		"en": "Set TopologyType to '3azones'.",
		"zh": "将 TopologyType 设置为'3azones'。",
		"ja": "TopologyType を '3azones' に設定します。",
		"de": "Setzen Sie TopologyType auf '3azones'.",
		"es": "Establezca TopologyType en '3azones'.",
		"fr": "Définissez TopologyType sur '3azones'.",
		"pt": "Defina TopologyType como '3azones'."
	},
	"resource_types": ["ALIYUN::PolarDBX::DBInstance"]
}

# Check if instance is multi-zone (3azones)
is_multi_zone(resource) if {
	resource.Properties.TopologyType == "3azones"
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TopologyType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
