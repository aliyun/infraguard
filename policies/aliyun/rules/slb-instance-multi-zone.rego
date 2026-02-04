package infraguard.rules.aliyun.slb_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
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
		"en": "Configure a slave zone by setting the SlaveZoneId property to enable multi-zone deployment.",
		"zh": "通过设置 SlaveZoneId 属性配置备可用区，以启用多可用区部署。",
		"ja": "SlaveZoneId プロパティを設定してスレーブゾーンを設定し、マルチゾーン展開を有効にします。",
		"de": "Konfigurieren Sie eine Slave-Zone, indem Sie die SlaveZoneId-Eigenschaft setzen, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure una zona esclava estableciendo la propiedad SlaveZoneId para habilitar la implementación multi-zona.",
		"fr": "Configurez une zone esclave en définissant la propriété SlaveZoneId pour activer le déploiement multi-zones.",
		"pt": "Configure uma zona escrava definindo a propriedade SlaveZoneId para habilitar a implantação multi-zona."
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"]
}

# Check if instance has slave zone configured
has_slave_zone(resource) if {
	helpers.has_property(resource, "SlaveZoneId")
	slave_zone := resource.Properties.SlaveZoneId
	slave_zone != ""
}

# Deny rule: SLB instances should have slave zone configured
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not has_slave_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SlaveZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
