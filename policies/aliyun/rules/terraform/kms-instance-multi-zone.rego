package infraguard.rules.terraform.kms_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "kms-instance-multi-zone",
	"severity": "high",
	"name": {
		"en": "KMS Instance Multi-Zone Deployment",
		"zh": "使用多可用区的 KMS 实例",
		"ja": "KMS インスタンスのマルチゾーン展開",
		"de": "KMS-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-Zona de Instancia KMS",
		"fr": "Déploiement Multi-Zone de l'Instance KMS",
		"pt": "Implantação Multi-Zona da Instância KMS"
	},
	"description": {
		"en": "KMS instances should be deployed across multiple availability zones for high availability. If only one zone is selected, a zone failure will affect the KMS instance and business stability.",
		"zh": "KMS 实例为多可用区实例，视为合规。如果只选择了一个可用区，当这个可用区出现故障时，会影响 KMS 实例，进而影响业务稳定性。",
		"ja": "KMS インスタンスは高可用性と災害復旧のために少なくとも 2 つの可用性ゾーンにまたがって展開する必要があります。",
		"de": "KMS-Instanzen sollten für hohe Verfügbarkeit und Disaster Recovery über mindestens zwei Verfügbarkeitszonen hinweg bereitgestellt werden.",
		"es": "Las instancias KMS deben desplegarse en al menos dos zonas de disponibilidad para alta disponibilidad y recuperación ante desastres.",
		"fr": "Les instances KMS doivent être déployées sur au moins deux zones de disponibilité pour une haute disponibilité et une reprise après sinistre.",
		"pt": "As instâncias KMS devem ser implantadas em pelo menos duas zonas de disponibilidade para alta disponibilidade e recuperação de desastres."
	},
	"reason": {
		"en": "The KMS instance is deployed in only one availability zone, which creates a single point of failure.",
		"zh": "KMS 实例仅部署在一个可用区，存在单点故障风险。",
		"ja": "KMS インスタンスが複数の可用性ゾーンで設定されていないため、可用性に影響を与える可能性があります。",
		"de": "Die KMS-Instanz ist nicht mit mehreren Verfügbarkeitszonen konfiguriert, was die Verfügbarkeit beeinträchtigen kann.",
		"es": "La instancia KMS no está configurada con múltiples zonas de disponibilidad, lo que puede afectar la disponibilidad.",
		"fr": "L'instance KMS n'est pas configurée avec plusieurs zones de disponibilité, ce qui peut affecter la disponibilité.",
		"pt": "A instância KMS não está configurada com múltiplas zonas de disponibilidade, o que pode afetar a disponibilidade."
	},
	"recommendation": {
		"en": "Configure the KMS instance to use at least two availability zones by specifying multiple zone_ids.",
		"zh": "通过指定多个 zone_ids，将 KMS 实例配置为使用至少两个可用区。",
		"ja": "マルチゾーン展開を有効にするために、Connection.ZoneIds プロパティで少なくとも 2 つの可用性ゾーンを設定します。",
		"de": "Konfigurieren Sie mindestens zwei Verfügbarkeitszonen in der Connection.ZoneIds-Eigenschaft, um Multi-Zone-Bereitstellung zu aktivieren.",
		"es": "Configure al menos dos zonas de disponibilidad en la propiedad Connection.ZoneIds para habilitar el despliegue multi-zona.",
		"fr": "Configurez au moins deux zones de disponibilité dans la propriété Connection.ZoneIds pour activer le déploiement multi-zones.",
		"pt": "Configure pelo menos duas zonas de disponibilidade na propriedade Connection.ZoneIds para habilitar a implantação multi-zona."
	},
	"resource_types": ["alicloud_kms_instance"],
	"iac_type": "terraform"
}

# Check if instance has multi-zone deployment
is_multi_zone(resource) if {
	zone_ids := tf.get_attribute(resource, "zone_ids", [])
	not tf.is_unknown(zone_ids)
	count(zone_ids) >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_kms_instance")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_kms_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
