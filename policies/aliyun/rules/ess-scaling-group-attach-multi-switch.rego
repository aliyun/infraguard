package infraguard.rules.aliyun.ess_scaling_group_attach_multi_switch

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-scaling-group-attach-multi-switch",
	"name": {
		"en": "ESS Scaling Group Multi-VSwitch",
		"zh": "弹性伸缩组关联至少两个交换机",
		"ja": "ESS スケーリンググループマルチ VSwitch",
		"de": "ESS-Skalierungsgruppe Multi-VSwitch",
		"es": "Grupo de Escalado ESS Multi-VSwitch",
		"fr": "Groupe de Mise à l'Échelle ESS Multi-VSwitch",
		"pt": "Grupo de Escalonamento ESS Multi-VSwitch",
	},
	"severity": "medium",
	"description": {
		"en": "ESS scaling groups should be associated with at least two VSwitches for high availability across multiple zones.",
		"zh": "弹性伸缩组关联至少两个交换机，视为合规。",
		"ja": "ESS スケーリンググループは、複数のゾーンにわたる高可用性のために少なくとも 2 つの VSwitch に関連付ける必要があります。",
		"de": "ESS-Skalierungsgruppen sollten für Hochverfügbarkeit über mehrere Zonen hinweg mit mindestens zwei VSwitches verknüpft sein.",
		"es": "Los grupos de escalado ESS deben estar asociados con al menos dos VSwitches para alta disponibilidad en múltiples zonas.",
		"fr": "Les groupes de mise à l'échelle ESS doivent être associés à au moins deux VSwitches pour une haute disponibilité sur plusieurs zones.",
		"pt": "Os grupos de escalonamento ESS devem estar associados a pelo menos dois VSwitches para alta disponibilidade em múltiplas zonas.",
	},
	"reason": {
		"en": "The ESS scaling group is associated with fewer than two VSwitches, which may affect availability.",
		"zh": "弹性伸缩组关联的交换机少于两个，可能影响可用性。",
		"ja": "ESS スケーリンググループが 2 つ未満の VSwitch に関連付けられており、可用性に影響を与える可能性があります。",
		"de": "Die ESS-Skalierungsgruppe ist mit weniger als zwei VSwitches verknüpft, was die Verfügbarkeit beeinträchtigen kann.",
		"es": "El grupo de escalado ESS está asociado con menos de dos VSwitches, lo que puede afectar la disponibilidad.",
		"fr": "Le groupe de mise à l'échelle ESS est associé à moins de deux VSwitches, ce qui peut affecter la disponibilité.",
		"pt": "O grupo de escalonamento ESS está associado a menos de dois VSwitches, o que pode afetar a disponibilidade.",
	},
	"recommendation": {
		"en": "Configure at least two VSwitches in the VSwitchIds property to ensure high availability across multiple zones.",
		"zh": "在 VSwitchIds 属性中配置至少两个交换机，以确保跨多个可用区的高可用性。",
		"ja": "複数のゾーンにわたる高可用性を確保するために、VSwitchIds プロパティで少なくとも 2 つの VSwitch を設定します。",
		"de": "Konfigurieren Sie mindestens zwei VSwitches in der VSwitchIds-Eigenschaft, um Hochverfügbarkeit über mehrere Zonen hinweg sicherzustellen.",
		"es": "Configure al menos dos VSwitches en la propiedad VSwitchIds para asegurar alta disponibilidad en múltiples zonas.",
		"fr": "Configurez au moins deux VSwitches dans la propriété VSwitchIds pour assurer une haute disponibilité sur plusieurs zones.",
		"pt": "Configure pelo menos dois VSwitches na propriedade VSwitchIds para garantir alta disponibilidade em múltiplas zonas.",
	},
	"resource_types": ["ALIYUN::ESS::ScalingGroup"],
}

# Check if scaling group has multiple VSwitches
has_multiple_vswitches(resource) if {
	vswitches := resource.Properties.VSwitchIds
	count(vswitches) >= 2
}

# Deny rule: ESS scaling groups must have at least two VSwitches
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingGroup")
	not has_multiple_vswitches(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VSwitchIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
