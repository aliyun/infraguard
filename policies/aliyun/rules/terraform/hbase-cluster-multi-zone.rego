package infraguard.rules.terraform.hbase_cluster_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "hbase-cluster-multi-zone",
	"severity": "medium",
	"name": {
		"en": "HBase Cluster Multi-Zone Deployment",
		"zh": "HBase 集群多可用区部署",
		"ja": "HBase クラスターマルチゾーン展開",
		"de": "HBase-Cluster Multi-Zonen-Bereitstellung",
		"es": "Implementacion Multi-Zona del Cluster HBase",
		"fr": "Deploiement Multi-Zone du Cluster HBase",
		"pt": "Implantacao Multi-Zona do Cluster HBase"
	},
	"description": {
		"en": "HBase cluster should have at least 2 core instances for multi-zone deployment capability.",
		"zh": "HBase 集群应至少有 2 个核心节点以支持多可用区部署。",
		"ja": "HBase クラスターはマルチゾーン展開のために少なくとも 2 つのコアインスタンスが必要です。",
		"de": "HBase-Cluster sollte fur Multi-Zonen-Bereitstellung mindestens 2 Kerninstanzen haben.",
		"es": "El cluster HBase debe tener al menos 2 instancias centrales para implementacion multi-zona.",
		"fr": "Le cluster HBase doit avoir au moins 2 instances coeur pour le deploiement multi-zone.",
		"pt": "O cluster HBase deve ter pelo menos 2 instancias centrais para implantacao multi-zona."
	},
	"reason": {
		"en": "The HBase cluster has fewer than 2 core instances, which does not support multi-zone deployment.",
		"zh": "HBase 集群核心节点数少于 2，不支持多可用区部署。",
		"ja": "HBase クラスターのコアインスタンスが 2 未満であり、マルチゾーン展開をサポートしていません。",
		"de": "Der HBase-Cluster hat weniger als 2 Kerninstanzen, was Multi-Zonen-Bereitstellung nicht unterstutzt.",
		"es": "El cluster HBase tiene menos de 2 instancias centrales, lo que no soporta implementacion multi-zona.",
		"fr": "Le cluster HBase a moins de 2 instances coeur, ce qui ne supporte pas le deploiement multi-zone.",
		"pt": "O cluster HBase tem menos de 2 instancias centrais, o que nao suporta implantacao multi-zona."
	},
	"recommendation": {
		"en": "Set core_instance_quantity to at least 2 for multi-zone deployment capability.",
		"zh": "将 core_instance_quantity 设置为至少 2 以支持多可用区部署。",
		"ja": "マルチゾーン展開のために core_instance_quantity を少なくとも 2 に設定します。",
		"de": "Setzen Sie core_instance_quantity auf mindestens 2 fur Multi-Zonen-Bereitstellung.",
		"es": "Configure core_instance_quantity a al menos 2 para capacidad de implementacion multi-zona.",
		"fr": "Definissez core_instance_quantity a au moins 2 pour la capacite de deploiement multi-zone.",
		"pt": "Defina core_instance_quantity como pelo menos 2 para capacidade de implantacao multi-zona."
	},
	"resource_types": ["alicloud_hbase_instance"],
	"iac_type": "terraform"
}

is_multi_zone(resource) if {
	quantity := tf.get_attribute(resource, "core_instance_quantity", 1)
	not tf.is_unknown(quantity)
	quantity >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_hbase_instance")
	not is_multi_zone(resource)
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
