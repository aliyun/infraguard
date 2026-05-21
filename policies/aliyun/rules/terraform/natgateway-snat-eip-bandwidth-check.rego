package infraguard.rules.terraform.natgateway_snat_eip_bandwidth_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "natgateway-snat-eip-bandwidth-check",
	"severity": "medium",
	"name": {
		"en": "NAT Gateway SNAT EIP Bandwidth Consistency",
		"zh": "NAT 网关 SNAT 条目绑定多个 EIP 时带宽峰值设置一致",
		"ja": "NAT ゲートウェイ SNAT EIP 帯域幅の一貫性",
		"de": "NAT-Gateway SNAT EIP-Bandbreitenkonsistenz",
		"es": "Consistencia de Ancho de Banda EIP SNAT de Puerta de Enlace NAT",
		"fr": "Cohérence de Bande Passante EIP SNAT de Passerelle NAT",
		"pt": "Consistência de Largura de Banda EIP SNAT do Gateway NAT"
	},
	"description": {
		"en": "NAT gateway specification should not be Small to ensure adequate SNAT EIP bandwidth capacity.",
		"zh": "NAT 网关规格不应为 Small，以确保足够的 SNAT EIP 带宽容量。",
		"ja": "NAT ゲートウェイの仕様は、十分な SNAT EIP 帯域幅容量を確保するために Small であってはなりません。",
		"de": "Die NAT-Gateway-Spezifikation sollte nicht Small sein, um eine ausreichende SNAT EIP-Bandbreitenkapazität sicherzustellen.",
		"es": "La especificación de la puerta de enlace NAT no debe ser Small para garantizar capacidad de ancho de banda EIP SNAT adecuada.",
		"fr": "La spécification de la passerelle NAT ne doit pas être Small pour garantir une capacité de bande passante EIP SNAT adéquate.",
		"pt": "A especificação do gateway NAT não deve ser Small para garantir capacidade adequada de largura de banda EIP SNAT."
	},
	"reason": {
		"en": "Small specification NAT gateways may not provide sufficient bandwidth for SNAT entries with multiple EIPs, leading to performance issues.",
		"zh": "Small 规格的 NAT 网关可能无法为绑定多个 EIP 的 SNAT 条目提供足够的带宽，导致性能问题。",
		"ja": "Small 仕様の NAT ゲートウェイは、複数の EIP を持つ SNAT エントリに十分な帯域幅を提供できない可能性があり、パフォーマンスの問題が発生する可能性があります。",
		"de": "NAT-Gateways mit Small-Spezifikation bieten möglicherweise nicht genügend Bandbreite für SNAT-Einträge mit mehreren EIPs, was zu Leistungsproblemen führen kann.",
		"es": "Las puertas de enlace NAT de especificación Small pueden no proporcionar suficiente ancho de banda para entradas SNAT con múltiples EIPs, causando problemas de rendimiento.",
		"fr": "Les passerelles NAT de spécification Small peuvent ne pas fournir suffisamment de bande passante pour les entrées SNAT avec plusieurs EIP, entraînant des problèmes de performance.",
		"pt": "Gateways NAT de especificação Small podem não fornecer largura de banda suficiente para entradas SNAT com múltiplos EIPs, causando problemas de desempenho."
	},
	"recommendation": {
		"en": "Set specification to 'Middle' or higher to ensure adequate bandwidth for SNAT EIP traffic.",
		"zh": "将规格设置为 'Middle' 或更高，以确保 SNAT EIP 流量有足够的带宽。",
		"ja": "SNAT EIP トラフィックに十分な帯域幅を確保するために、仕様を 'Middle' 以上に設定します。",
		"de": "Setzen Sie die Spezifikation auf 'Middle' oder höher, um ausreichende Bandbreite für SNAT EIP-Verkehr sicherzustellen.",
		"es": "Establezca la especificación en 'Middle' o superior para garantizar un ancho de banda adecuado para el tráfico EIP SNAT.",
		"fr": "Définissez la spécification sur 'Middle' ou supérieur pour garantir une bande passante adéquate pour le trafic EIP SNAT.",
		"pt": "Defina a especificação como 'Middle' ou superior para garantir largura de banda adequada para tráfego EIP SNAT."
	},
	"resource_types": ["alicloud_nat_gateway"],
	"iac_type": "terraform"
}

disallowed_specs := {"Small"}

is_compliant(resource) if {
	nat_type := tf.get_attribute(resource, "nat_type", "")
	nat_type == "Enhanced"
}

is_compliant(resource) if {
	spec := tf.get_attribute(resource, "specification", "")
	not tf.is_unknown(spec)
	spec != ""
	not spec in disallowed_specs
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_nat_gateway")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_nat_gateway.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
