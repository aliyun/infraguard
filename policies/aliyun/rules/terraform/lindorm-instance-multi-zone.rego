package infraguard.rules.terraform.lindorm_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "lindorm-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "Lindorm Instance Multi-Zone Deployment",
		"zh": "Lindorm 实例多可用区部署",
		"ja": "Lindorm インスタンスのマルチゾーン展開",
		"de": "Lindorm-Instanz Multi-Zonen-Bereitstellung",
		"es": "Despliegue Multi-zona de Instancia Lindorm",
		"fr": "Déploiement Multi-Zones d'Instance Lindorm",
		"pt": "Implantação Multi-zona de Instância Lindorm"
	},
	"description": {
		"en": "Lindorm instance should have at least 4 table engine nodes for multi-zone deployment capability.",
		"zh": "Lindorm 实例应至少有 4 个表引擎节点以支持多可用区部署。",
		"ja": "Lindorm インスタンスはマルチゾーン展開のために少なくとも 4 つのテーブルエンジンノードが必要です。",
		"de": "Lindorm-Instanz sollte für Multi-Zonen-Bereitstellung mindestens 4 Tabellenengine-Knoten haben.",
		"es": "La instancia Lindorm debe tener al menos 4 nodos de motor de tabla para implementación multi-zona.",
		"fr": "L'instance Lindorm doit avoir au moins 4 noeuds de moteur de table pour le déploiement multi-zone.",
		"pt": "A instância Lindorm deve ter pelo menos 4 nós de motor de tabela para implantação multi-zona."
	},
	"reason": {
		"en": "The Lindorm instance has fewer than 4 table engine nodes, which does not support multi-zone deployment.",
		"zh": "Lindorm 实例表引擎节点数少于 4，不支持多可用区部署。",
		"ja": "Lindorm インスタンスのテーブルエンジンノードが 4 未満であり、マルチゾーン展開をサポートしていません。",
		"de": "Die Lindorm-Instanz hat weniger als 4 Tabellenengine-Knoten, was Multi-Zonen-Bereitstellung nicht unterstützt.",
		"es": "La instancia Lindorm tiene menos de 4 nodos de motor de tabla, lo que no soporta implementación multi-zona.",
		"fr": "L'instance Lindorm a moins de 4 noeuds de moteur de table, ce qui ne supporte pas le déploiement multi-zone.",
		"pt": "A instância Lindorm tem menos de 4 nós de motor de tabela, o que não suporta implantação multi-zona."
	},
	"recommendation": {
		"en": "Set table_engine_node_count to at least 4 for multi-zone deployment capability.",
		"zh": "将 table_engine_node_count 设置为至少 4 以支持多可用区部署。",
		"ja": "マルチゾーン展開のために table_engine_node_count を少なくとも 4 に設定します。",
		"de": "Setzen Sie table_engine_node_count auf mindestens 4 für Multi-Zonen-Bereitstellung.",
		"es": "Configure table_engine_node_count a al menos 4 para capacidad de implementación multi-zona.",
		"fr": "Définissez table_engine_node_count à au moins 4 pour la capacité de déploiement multi-zone.",
		"pt": "Defina table_engine_node_count como pelo menos 4 para capacidade de implantação multi-zona."
	},
	"resource_types": ["alicloud_lindorm_instance"],
	"iac_type": "terraform"
}

is_multi_zone(resource) if {
	count := tf.get_attribute(resource, "table_engine_node_count", 0)
	not tf.is_unknown(count)
	count >= 4
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_lindorm_instance")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_lindorm_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
