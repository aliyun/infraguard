package infraguard.rules.aliyun.rds_multi_az_support

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rds-multi-az-support",
	"name": {
		"en": "RDS Instance Multi-AZ Deployment",
		"zh": "RDS 实例多可用区部署",
		"ja": "RDS インスタンスのマルチ AZ 展開",
		"de": "RDS-Instanz Multi-AZ-Bereitstellung",
		"es": "Despliegue Multi-AZ de Instancia RDS",
		"fr": "Déploiement Multi-AZ d'Instance RDS",
		"pt": "Implantação Multi-AZ de Instância RDS",
	},
	"severity": "medium",
	"description": {
		"en": "RDS instances should be deployed in multi-AZ configuration for high availability and automatic failover.",
		"zh": "RDS 实例应部署在多可用区配置中，以实现高可用性和自动故障转移。",
		"ja": "RDS インスタンスは、高可用性と自動フェイルオーバーのためにマルチ AZ 構成で展開する必要があります。",
		"de": "RDS-Instanzen sollten für hohe Verfügbarkeit und automatisches Failover in Multi-AZ-Konfiguration bereitgestellt werden.",
		"es": "Las instancias RDS deben implementarse en configuración multi-AZ para alta disponibilidad y conmutación por error automática.",
		"fr": "Les instances RDS doivent être déployées en configuration multi-AZ pour une haute disponibilité et un basculement automatique.",
		"pt": "Instâncias RDS devem ser implantadas em configuração multi-AZ para alta disponibilidade e failover automático.",
	},
	"reason": {
		"en": "The RDS instance is not deployed in multi-AZ configuration, which may affect availability during zone failures.",
		"zh": "RDS 实例未部署在多可用区配置中，在可用区故障时可能影响可用性。",
		"ja": "RDS インスタンスがマルチ AZ 構成で展開されていないため、ゾーン障害時に可用性に影響を与える可能性があります。",
		"de": "Die RDS-Instanz ist nicht in Multi-AZ-Konfiguration bereitgestellt, was die Verfügbarkeit bei Zonenausfällen beeinträchtigen kann.",
		"es": "La instancia RDS no está implementada en configuración multi-AZ, lo que puede afectar la disponibilidad durante fallas de zona.",
		"fr": "L'instance RDS n'est pas déployée en configuration multi-AZ, ce qui peut affecter la disponibilité lors de pannes de zone.",
		"pt": "A instância RDS não está implantada em configuração multi-AZ, o que pode afetar a disponibilidade durante falhas de zona.",
	},
	"recommendation": {
		"en": "Enable multi-AZ deployment by setting MultiAZ to true when creating the instance.",
		"zh": "在创建实例时通过将 MultiAZ 设置为 true 来启用多可用区部署。",
		"ja": "インスタンス作成時に MultiAZ を true に設定して、マルチ AZ 展開を有効にします。",
		"de": "Aktivieren Sie Multi-AZ-Bereitstellung, indem Sie MultiAZ beim Erstellen der Instanz auf true setzen.",
		"es": "Habilite la implementación multi-AZ estableciendo MultiAZ en true al crear la instancia.",
		"fr": "Activez le déploiement multi-AZ en définissant MultiAZ sur true lors de la création de l'instance.",
		"pt": "Habilite implantação multi-AZ definindo MultiAZ como true ao criar a instância.",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

# Check if instance has multi-AZ enabled
has_multi_az_enabled(resource) if {
	multi_az := helpers.get_property(resource, "MultiAZ", false)
	multi_az == true
}

# Deny rule: RDS instances should have multi-AZ enabled
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not has_multi_az_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "MultiAZ"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
