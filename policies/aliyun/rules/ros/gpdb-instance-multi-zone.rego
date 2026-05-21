package infraguard.rules.aliyun.gpdb_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "gpdb-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "GPDB Instance Multi-Zone Deployment",
		"zh": "使用多可用区的云原生数据仓库 AnalyticDB 实例",
		"ja": "GPDB インスタンスマルチゾーン展開",
		"de": "GPDB-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia GPDB",
		"fr": "Déploiement Multi-Zone d'Instance GPDB",
		"pt": "Implantações Multi-Zona de Instância GPDB"
	},
	"description": {
		"en": "GPDB instances should be deployed with a standby zone for high availability.",
		"zh": "使用多可用区的云原生数据仓库 AnalyticDB 实例，视为合规。",
		"ja": "GPDB インスタンスは高可用性のためにスタンバイゾーンで展開する必要があります。",
		"de": "GPDB-Instanzen sollten mit einer Standby-Zone für Hochverfügbarkeit bereitgestellt werden.",
		"es": "Las instancias GPDB deben desplegarse con una zona de espera para alta disponibilidad.",
		"fr": "Les instances GPDB doivent être déployées avec une zone de secours pour une haute disponibilité.",
		"pt": "As instâncias GPDB devem ser implantadas com uma zona de espera para alta disponibilidade."
	},
	"reason": {
		"en": "The GPDB instance does not have a standby zone configured, which may affect availability.",
		"zh": "GPDB 实例未配置备用可用区，可能影响可用性。",
		"ja": "GPDB インスタンスにスタンバイゾーンが設定されておらず、可用性に影響を与える可能性があります。",
		"de": "Die GPDB-Instanz hat keine Standby-Zone konfiguriert, was die Verfügbarkeit beeinträchtigen kann.",
		"es": "La instancia GPDB no tiene una zona de espera configurada, lo que puede afectar la disponibilidad.",
		"fr": "L'instance GPDB n'a pas de zone de secours configurée, ce qui peut affecter la disponibilité.",
		"pt": "A instância GPDB não tem uma zona de espera configurada, o que pode afetar a disponibilidade."
	},
	"recommendation": {
		"en": "Configure a standby zone by setting the StandbyZoneId property to enable multi-zone deployment.",
		"zh": "通过设置 StandbyZoneId 属性配置备用可用区，以启用多可用区部署。",
		"ja": "StandbyZoneId プロパティを設定してスタンバイゾーンを設定し、マルチゾーン展開を有効にします。",
		"de": "Konfigurieren Sie eine Standby-Zone, indem Sie die StandbyZoneId-Eigenschaft setzen, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure una zona de espera estableciendo la propiedad StandbyZoneId para habilitar el despliegue multi-zona.",
		"fr": "Configurez une zone de secours en définissant la propriété StandbyZoneId pour activer le déploiement multi-zone.",
		"pt": "Configure uma zona de espera definindo a propriedade StandbyZoneId para habilitar a implantação multi-zona."
	},
	"resource_types": ["ALIYUN::GPDB::DBInstance"]
}

# Check if instance has standby zone
has_standby_zone(resource) if {
	helpers.has_property(resource, "StandbyZoneId")
	standby_zone := resource.Properties.StandbyZoneId
	standby_zone != ""
}

# Deny rule: GPDB instances should have standby zone
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::GPDB::DBInstance")
	not has_standby_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "StandbyZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
