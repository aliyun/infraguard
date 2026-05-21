package infraguard.rules.terraform.rds_multi_az_support

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-multi-az-support",
	"severity": "medium",
	"name": {
		"en": "RDS Instance Multi-AZ Deployment",
		"zh": "RDS 实例多可用区部署",
		"ja": "RDS インスタンスのマルチ AZ 展開",
		"de": "RDS-Instanz Multi-AZ-Bereitstellung",
		"es": "Despliegue Multi-AZ de Instancia RDS",
		"fr": "Déploiement Multi-AZ d'Instance RDS",
		"pt": "Implantação Multi-AZ de Instância RDS"
	},
	"description": {
		"en": "RDS instances should be deployed in multi-AZ configuration for high availability and automatic failover.",
		"zh": "RDS 实例应部署在多可用区配置中，以实现高可用性和自动故障转移。",
		"ja": "RDS インスタンスは、高可用性と自動フェイルオーバーのためにマルチ AZ 構成で展開する必要があります。",
		"de": "RDS-Instanzen sollten für hohe Verfügbarkeit und automatisches Failover in Multi-AZ-Konfiguration bereitgestellt werden.",
		"es": "Las instancias RDS deben implementarse en configuración multi-AZ para alta disponibilidad y conmutación por error automática.",
		"fr": "Les instances RDS doivent être déployées en configuration multi-AZ pour une haute disponibilité et un basculement automatique.",
		"pt": "Instâncias RDS devem ser implantadas em configuração multi-AZ para alta disponibilidade e failover automático."
	},
	"reason": {
		"en": "The RDS instance is not deployed in multi-AZ configuration, which may affect availability during zone failures.",
		"zh": "RDS 实例未部署在多可用区配置中，在可用区故障时可能影响可用性。",
		"ja": "RDS インスタンスがマルチ AZ 構成で展開されていないため、ゾーン障害時に可用性に影響を与える可能性があります。",
		"de": "Die RDS-Instanz ist nicht in Multi-AZ-Konfiguration bereitgestellt, was die Verfügbarkeit bei Zonenausfällen beeinträchtigen kann.",
		"es": "La instancia RDS no está implementada en configuración multi-AZ, lo que puede afectar la disponibilidad durante fallas de zona.",
		"fr": "L'instance RDS n'est pas déployée en configuration multi-AZ, ce qui peut affecter la disponibilité lors de pannes de zone.",
		"pt": "A instância RDS não está implantada em configuração multi-AZ, o que pode afetar a disponibilidade durante falhas de zona."
	},
	"recommendation": {
		"en": "Set zone_id_slave_a to specify a slave zone for multi-AZ deployment.",
		"zh": "设置 zone_id_slave_a 以指定备用可用区，实现多可用区部署。",
		"ja": "zone_id_slave_a を設定してマルチ AZ 展開用のスレーブゾーンを指定します。",
		"de": "Setzen Sie zone_id_slave_a, um eine Slave-Zone für Multi-AZ-Bereitstellung anzugeben.",
		"es": "Establezca zone_id_slave_a para especificar una zona esclava para despliegue multi-AZ.",
		"fr": "Définissez zone_id_slave_a pour spécifier une zone esclave pour le déploiement multi-AZ.",
		"pt": "Defina zone_id_slave_a para especificar uma zona escrava para implantação multi-AZ."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	zone_slave := tf.get_attribute(resource, "zone_id_slave_a", "")
	zone_slave == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
