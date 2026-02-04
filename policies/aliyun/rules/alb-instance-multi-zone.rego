package infraguard.rules.aliyun.alb_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "alb-instance-multi-zone",
	"name": {
		"en": "ALB Instance Multi-Zone Deployment",
		"zh": "使用多可用区的 ALB 实例",
		"ja": "ALB インスタンスのマルチゾーン展開",
		"de": "ALB-Instanz Multi-Zone-Bereitstellung",
		"es": "Despliegue Multi-zona de Instancia ALB",
		"fr": "Déploiement Multi-Zones de l'Instance ALB",
		"pt": "Implantação Multi-zona da Instância ALB",
	},
	"severity": "high",
	"description": {
		"en": "ALB instances should be deployed across multiple availability zones for high availability. If only one zone is selected, a zone failure will affect the ALB instance and business stability.",
		"zh": "ALB 实例为多可用区实例，视为合规。如果只选择了一个可用区，当这个可用区出现故障时，会影响 ALB 实例，进而影响业务稳定性。",
		"ja": "高可用性のために、ALB インスタンスは複数の可用性ゾーンに展開する必要があります。1 つのゾーンのみを選択した場合、ゾーンの障害が ALB インスタンスとビジネスの安定性に影響します。",
		"de": "ALB-Instanzen sollten für hohe Verfügbarkeit über mehrere Verfügbarkeitszonen bereitgestellt werden. Wenn nur eine Zone ausgewählt wird, wirkt sich ein Zonenausfall auf die ALB-Instanz und die Geschäftsstabilität aus.",
		"es": "Las instancias ALB deben implementarse en múltiples zonas de disponibilidad para alta disponibilidad. Si solo se selecciona una zona, una falla en la zona afectará la instancia ALB y la estabilidad del negocio.",
		"fr": "Les instances ALB doivent être déployées sur plusieurs zones de disponibilité pour une haute disponibilité. Si une seule zone est sélectionnée, une panne de zone affectera l'instance ALB et la stabilité de l'entreprise.",
		"pt": "Instâncias ALB devem ser implantadas em múltiplas zonas de disponibilidade para alta disponibilidade. Se apenas uma zona for selecionada, uma falha na zona afetará a instância ALB e a estabilidade do negócio.",
	},
	"reason": {
		"en": "The ALB instance is deployed in only one availability zone, which creates a single point of failure.",
		"zh": "ALB 实例仅部署在一个可用区，存在单点故障风险。",
		"ja": "ALB インスタンスが 1 つの可用性ゾーンにのみ展開されているため、単一障害点が発生します。",
		"de": "Die ALB-Instanz ist nur in einer Verfügbarkeitszone bereitgestellt, was einen Single Point of Failure schafft.",
		"es": "La instancia ALB está implementada en solo una zona de disponibilidad, lo que crea un punto único de falla.",
		"fr": "L'instance ALB est déployée dans une seule zone de disponibilité, ce qui crée un point de défaillance unique.",
		"pt": "A instância ALB está implantada em apenas uma zona de disponibilidade, criando um ponto único de falha.",
	},
	"recommendation": {
		"en": "Configure the ALB instance to use at least two availability zones by adding multiple zone mappings in the ZoneMappings property.",
		"zh": "通过在 ZoneMappings 属性中添加多个可用区映射，将 ALB 实例配置为使用至少两个可用区。",
		"ja": "ZoneMappings プロパティに複数のゾーンマッピングを追加して、ALB インスタンスを少なくとも 2 つの可用性ゾーンを使用するように設定します。",
		"de": "Konfigurieren Sie die ALB-Instanz so, dass sie mindestens zwei Verfügbarkeitszonen verwendet, indem Sie mehrere Zonen-Zuordnungen in der ZoneMappings-Eigenschaft hinzufügen.",
		"es": "Configure la instancia ALB para usar al menos dos zonas de disponibilidad agregando múltiples mapeos de zona en la propiedad ZoneMappings.",
		"fr": "Configurez l'instance ALB pour utiliser au moins deux zones de disponibilité en ajoutant plusieurs mappages de zone dans la propriété ZoneMappings.",
		"pt": "Configure a instância ALB para usar pelo menos duas zonas de disponibilidade adicionando múltiplos mapeamentos de zona na propriedade ZoneMappings.",
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"],
}

# Check if ALB is multi-zone
is_multi_zone(resource) if {
	count(object.get(resource.Properties, "ZoneMappings", [])) >= 2
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ZoneMappings"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
