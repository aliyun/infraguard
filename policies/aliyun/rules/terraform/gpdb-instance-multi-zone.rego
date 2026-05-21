package infraguard.rules.terraform.gpdb_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "gpdb-instance-multi-zone",
	"severity": "high",
	"name": {
		"en": "GPDB Instance Multi-Zone Deployment",
		"zh": "GPDB 实例多可用区部署",
		"ja": "GPDB インスタンスマルチゾーン展開",
		"de": "GPDB-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia GPDB",
		"fr": "Déploiement Multi-Zone d'Instance GPDB",
		"pt": "Implantações Multi-Zona de Instância GPDB"
	},
	"description": {
		"en": "GPDB instances should be deployed across multiple availability zones for high availability.",
		"zh": "GPDB 实例应部署在多个可用区以实现高可用，视为合规。",
		"ja": "GPDB インスタンスは高可用性のためにスタンバイゾーンで展開する必要があります。",
		"de": "GPDB-Instanzen sollten mit einer Standby-Zone für Hochverfügbarkeit bereitgestellt werden.",
		"es": "Las instancias GPDB deben desplegarse con una zona de espera para alta disponibilidad.",
		"fr": "Les instances GPDB doivent être déployées avec une zone de secours pour une haute disponibilité.",
		"pt": "As instâncias GPDB devem ser implantadas com uma zona de espera para alta disponibilidade."
	},
	"reason": {
		"en": "The GPDB instance does not have a standby zone configured for multi-zone deployment.",
		"zh": "GPDB 实例未配置备可用区，未实现多可用区部署。",
		"ja": "GPDB インスタンスにスタンバイゾーンが設定されておらず、可用性に影響を与える可能性があります。",
		"de": "Die GPDB-Instanz hat keine Standby-Zone konfiguriert, was die Verfügbarkeit beeinträchtigen kann.",
		"es": "La instancia GPDB no tiene una zona de espera configurada, lo que puede afectar la disponibilidad.",
		"fr": "L'instance GPDB n'a pas de zone de secours configurée, ce qui peut affecter la disponibilité.",
		"pt": "A instância GPDB não tem uma zona de espera configurada, o que pode afetar a disponibilidade."
	},
	"recommendation": {
		"en": "Configure multi-zone deployment by specifying the standby_zone_id attribute with a valid availability zone.",
		"zh": "通过指定 standby_zone_id 属性并设置有效的可用区来配置多可用区部署。",
		"ja": "StandbyZoneId プロパティを設定してスタンバイゾーンを設定し、マルチゾーン展開を有効にします。",
		"de": "Konfigurieren Sie eine Standby-Zone, indem Sie die StandbyZoneId-Eigenschaft setzen, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure una zona de espera estableciendo la propiedad StandbyZoneId para habilitar el despliegue multi-zona.",
		"fr": "Configurez une zone de secours en définissant la propriété StandbyZoneId pour activer le déploiement multi-zone.",
		"pt": "Configure uma zona de espera definindo a propriedade StandbyZoneId para habilitar a implantação multi-zona."
	},
	"resource_types": ["alicloud_gpdb_instance"],
	"iac_type": "terraform"
}

# Check if multi-zone is configured
is_multi_zone(resource) if {
	standby_zone := tf.get_attribute(resource, "standby_zone_id", "")
	not tf.is_unknown(standby_zone)
	standby_zone != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_gpdb_instance")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_gpdb_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
