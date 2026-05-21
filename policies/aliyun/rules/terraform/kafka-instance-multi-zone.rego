package infraguard.rules.terraform.kafka_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "kafka-instance-multi-zone",
	"severity": "high",
	"name": {
		"en": "Kafka Instance Multi-Zone Deployment",
		"zh": "Kafka 实例多可用区部署",
		"ja": "Kafka インスタンスのマルチゾーン展開",
		"de": "Kafka-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-zona de Instancia Kafka",
		"fr": "Déploiement Multi-Zones de l'Instance Kafka",
		"pt": "Implantação Multi-zona da Instância Kafka"
	},
	"description": {
		"en": "Kafka instances should be deployed across multiple availability zones for high availability. If only one zone is selected, a zone failure will affect the Kafka instance and business stability.",
		"zh": "Kafka 实例应部署在多个可用区以实现高可用。如果只选择了一个可用区，当该可用区故障时会影响 Kafka 实例及业务稳定性。",
		"ja": "高可用性のために、Kafka インスタンスは複数の可用性ゾーンに展開する必要があります。1 つのゾーンのみを選択した場合、ゾーンの障害が Kafka インスタンスとビジネスの安定性に影響します。",
		"de": "Kafka-Instanzen sollten für hohe Verfügbarkeit über mehrere Verfügbarkeitszonen bereitgestellt werden. Wenn nur eine Zone ausgewählt wird, wirkt sich ein Zonenausfall auf die Kafka-Instanz und die Geschäftsstabilität aus.",
		"es": "Las instancias Kafka deben implementarse en múltiples zonas de disponibilidad para alta disponibilidad. Si solo se selecciona una zona, una falla en la zona afectará la instancia Kafka y la estabilidad del negocio.",
		"fr": "Les instances Kafka doivent être déployées sur plusieurs zones de disponibilité pour une haute disponibilité. Si une seule zone est sélectionnée, une panne de zone affectera l'instance Kafka et la stabilité de l'entreprise.",
		"pt": "Instâncias Kafka devem ser implantadas em múltiplas zonas de disponibilidade para alta disponibilidade. Se apenas uma zona for selecionada, uma falha na zona afetará a instância Kafka e a estabilidade do negócio."
	},
	"reason": {
		"en": "The Kafka instance is deployed in fewer than two availability zones, which creates a single point of failure.",
		"zh": "Kafka 实例部署在少于两个可用区，存在单点故障风险。",
		"ja": "Kafka インスタンスが 2 つ未満の可用性ゾーンに展開されているため、単一障害点が発生します。",
		"de": "Die Kafka-Instanz ist in weniger als zwei Verfügbarkeitszonen bereitgestellt, was einen Single Point of Failure schafft.",
		"es": "La instancia Kafka está implementada en menos de dos zonas de disponibilidad, lo que crea un punto único de falla.",
		"fr": "L'instance Kafka est déployée dans moins de deux zones de disponibilité, ce qui crée un point de défaillance unique.",
		"pt": "A instância Kafka está implantada em menos de duas zonas de disponibilidade, criando um ponto único de falha."
	},
	"recommendation": {
		"en": "Configure the Kafka instance to use at least two availability zones by specifying multiple zones in the selected_zones attribute.",
		"zh": "通过在 selected_zones 属性中指定多个可用区，将 Kafka 实例配置为使用至少两个可用区。",
		"ja": "selected_zones 属性に複数のゾーンを指定して、Kafka インスタンスを少なくとも 2 つの可用性ゾーンを使用するように設定します。",
		"de": "Konfigurieren Sie die Kafka-Instanz so, dass sie mindestens zwei Verfügbarkeitszonen verwendet, indem Sie mehrere Zonen im selected_zones-Attribut angeben.",
		"es": "Configure la instancia Kafka para usar al menos dos zonas de disponibilidad especificando múltiples zonas en el atributo selected_zones.",
		"fr": "Configurez l'instance Kafka pour utiliser au moins deux zones de disponibilité en spécifiant plusieurs zones dans l'attribut selected_zones.",
		"pt": "Configure a instância Kafka para usar pelo menos duas zonas de disponibilidade especificando múltiplas zonas no atributo selected_zones."
	},
	"resource_types": ["alicloud_alikafka_instance"],
	"iac_type": "terraform"
}

is_multi_zone(resource) if {
	zones := tf.get_attribute(resource, "selected_zones", [])
	not tf.is_unknown(zones)
	count(zones) >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_alikafka_instance")
	not is_multi_zone(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_alikafka_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
