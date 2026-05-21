package infraguard.rules.terraform.slb_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "SLB Instance Multi-Zone Deployment",
		"zh": "SLB 实例多可用区部署",
		"ja": "SLB インスタンスのマルチゾーン展開",
		"de": "SLB-Instanz Multi-Zone-Bereitstellung",
		"es": "Implementación Multi-zona de Instancia SLB",
		"fr": "Déploiement Multi-zones de l'Instance SLB",
		"pt": "Implantação Multi-zona da Instância SLB"
	},
	"description": {
		"en": "SLB instances should be deployed across multiple zones by configuring both master and slave zones for high availability.",
		"zh": "SLB 实例应通过配置主可用区和备可用区来部署在多个可用区，以实现高可用性。",
		"ja": "SLB インスタンスは、高可用性のためにマスターゾーンとスレーブゾーンの両方を設定して、複数のゾーンに展開する必要があります。",
		"de": "SLB-Instanzen sollten über mehrere Zonen hinweg bereitgestellt werden, indem sowohl Master- als auch Slave-Zonen für hohe Verfügbarkeit konfiguriert werden.",
		"es": "Las instancias SLB deben implementarse en múltiples zonas configurando zonas maestra y esclava para alta disponibilidad.",
		"fr": "Les instances SLB doivent être déployées sur plusieurs zones en configurant à la fois les zones maître et esclave pour une haute disponibilité.",
		"pt": "Instâncias SLB devem ser implantadas em múltiplas zonas configurando zonas mestre e escrava para alta disponibilidade."
	},
	"reason": {
		"en": "The SLB instance does not have a slave zone configured, which may affect availability during zone failures.",
		"zh": "SLB 实例未配置备可用区，在可用区故障时可能影响可用性。",
		"ja": "SLB インスタンスにスレーブゾーンが設定されていないため、ゾーン障害時に可用性に影響を与える可能性があります。",
		"de": "Die SLB-Instanz hat keine Slave-Zone konfiguriert, was die Verfügbarkeit während Zonenausfällen beeinträchtigen kann.",
		"es": "La instancia SLB no tiene una zona esclava configurada, lo que puede afectar la disponibilidad durante fallas de zona.",
		"fr": "L'instance SLB n'a pas de zone esclave configurée, ce qui peut affecter la disponibilité lors de pannes de zone.",
		"pt": "A instância SLB não tem uma zona escrava configurada, o que pode afetar a disponibilidade durante falhas de zona."
	},
	"recommendation": {
		"en": "Configure slave_zone_id to enable multi-zone deployment.",
		"zh": "配置 slave_zone_id 以启用多可用区部署。",
		"ja": "マルチゾーン展開を有効にするために slave_zone_id を設定します。",
		"de": "Konfigurieren Sie slave_zone_id, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure slave_zone_id para habilitar la implementación multi-zona.",
		"fr": "Configurez slave_zone_id pour activer le déploiement multi-zones.",
		"pt": "Configure slave_zone_id para habilitar a implantação multi-zona."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

has_slave_zone(resource) if {
	value := tf.get_attribute(resource, "slave_zone_id", "")
	not tf.is_unknown(value)
	value != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	not has_slave_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_load_balancer.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
