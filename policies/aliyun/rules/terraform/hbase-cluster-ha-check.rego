package infraguard.rules.terraform.hbase_cluster_ha_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "hbase-cluster-ha-check",
	"severity": "high",
	"name": {
		"en": "HBase Cluster High Availability Check",
		"zh": "HBase 集群高可用检查",
		"ja": "HBase クラスター高可用性チェック",
		"de": "HBase-Cluster Hochverfugbarkeit Prufung",
		"es": "Verificacion de Alta Disponibilidad del Cluster HBase",
		"fr": "Verification de Haute Disponibilite du Cluster HBase",
		"pt": "Verificacao de Alta Disponibilidade do Cluster HBase"
	},
	"description": {
		"en": "HBase cluster should have at least 2 core instances for high availability.",
		"zh": "HBase 集群应至少有 2 个核心节点以确保高可用。",
		"ja": "HBase クラスターは高可用性のために少なくとも 2 つのコアインスタンスが必要です。",
		"de": "HBase-Cluster sollte fur Hochverfugbarkeit mindestens 2 Kerninstanzen haben.",
		"es": "El cluster HBase debe tener al menos 2 instancias centrales para alta disponibilidad.",
		"fr": "Le cluster HBase doit avoir au moins 2 instances coeur pour la haute disponibilite.",
		"pt": "O cluster HBase deve ter pelo menos 2 instancias centrais para alta disponibilidade."
	},
	"reason": {
		"en": "The HBase cluster has fewer than 2 core instances, which does not meet high availability requirements.",
		"zh": "HBase 集群核心节点数少于 2，不满足高可用要求。",
		"ja": "HBase クラスターのコアインスタンスが 2 未満であり、高可用性要件を満たしていません。",
		"de": "Der HBase-Cluster hat weniger als 2 Kerninstanzen, was die Hochverfugbarkeitsanforderungen nicht erfullt.",
		"es": "El cluster HBase tiene menos de 2 instancias centrales, lo que no cumple con los requisitos de alta disponibilidad.",
		"fr": "Le cluster HBase a moins de 2 instances coeur, ce qui ne repond pas aux exigences de haute disponibilite.",
		"pt": "O cluster HBase tem menos de 2 instancias centrais, o que nao atende aos requisitos de alta disponibilidade."
	},
	"recommendation": {
		"en": "Set core_instance_quantity to at least 2 for the HBase instance.",
		"zh": "将 HBase 实例的 core_instance_quantity 设置为至少 2。",
		"ja": "HBase インスタンスの core_instance_quantity を少なくとも 2 に設定します。",
		"de": "Setzen Sie core_instance_quantity fur die HBase-Instanz auf mindestens 2.",
		"es": "Configure core_instance_quantity a al menos 2 para la instancia HBase.",
		"fr": "Definissez core_instance_quantity a au moins 2 pour l'instance HBase.",
		"pt": "Defina core_instance_quantity como pelo menos 2 para a instancia HBase."
	},
	"resource_types": ["alicloud_hbase_instance"],
	"iac_type": "terraform"
}

is_ha(resource) if {
	quantity := tf.get_attribute(resource, "core_instance_quantity", 1)
	not tf.is_unknown(quantity)
	quantity >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_hbase_instance")
	not is_ha(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_hbase_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
