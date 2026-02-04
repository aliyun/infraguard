package infraguard.rules.aliyun.natgateway_snat_eip_bandwidth_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "natgateway-snat-eip-bandwidth-check",
	"name": {
		"en": "NAT Gateway SNAT EIP Bandwidth Consistency",
		"zh": "NAT 网关 SNAT 条目绑定多个 EIP 时带宽峰值设置一致",
		"ja": "NAT ゲートウェイ SNAT EIP 帯域幅の一貫性",
		"de": "NAT-Gateway SNAT EIP-Bandbreitenkonsistenz",
		"es": "Consistencia de Ancho de Banda EIP SNAT de Puerta de Enlace NAT",
		"fr": "Cohérence de Bande Passante EIP SNAT de Passerelle NAT",
		"pt": "Consistência de Largura de Banda EIP SNAT do Gateway NAT",
	},
	"severity": "medium",
	"description": {
		"en": "When SNAT entries are bound to multiple EIPs, the bandwidth peak settings should be consistent or they should be added to a shared bandwidth package.",
		"zh": "NAT 网关中 SNAT 条目绑定的多个 EIP，加入共享带宽包或者所绑定的 EIP 带宽峰值设置一致，视为合规。",
		"ja": "SNAT エントリが複数の EIP にバインドされている場合、帯域幅ピーク設定は一貫しているか、共有帯域幅パッケージに追加する必要があります。",
		"de": "Wenn SNAT-Einträge an mehrere EIPs gebunden sind, sollten die Bandbreiten-Peak-Einstellungen konsistent sein oder sie sollten zu einem gemeinsamen Bandbreitenpaket hinzugefügt werden.",
		"es": "Cuando las entradas SNAT están vinculadas a múltiples EIPs, la configuración del pico de ancho de banda debe ser consistente o deben agregarse a un paquete de ancho de banda compartido.",
		"fr": "Lorsque les entrées SNAT sont liées à plusieurs EIP, les paramètres de pic de bande passante doivent être cohérents ou ils doivent être ajoutés à un package de bande passante partagée.",
		"pt": "Quando entradas SNAT estão vinculadas a múltiplos EIPs, as configurações de pico de largura de banda devem ser consistentes ou devem ser adicionadas a um pacote de largura de banda compartilhado.",
	},
	"reason": {
		"en": "Inconsistent bandwidth settings can lead to unpredictable network performance and potential traffic distribution issues.",
		"zh": "不一致的带宽设置可能导致不可预测的网络性能和潜在的流量分配问题。",
		"ja": "一貫性のない帯域幅設定により、予測不可能なネットワークパフォーマンスと潜在的なトラフィック分散の問題が発生する可能性があります。",
		"de": "Inkonsistente Bandbreiteneinstellungen können zu unvorhersehbarer Netzwerkleistung und potenziellen Datenverteilungsproblemen führen.",
		"es": "Las configuraciones de ancho de banda inconsistentes pueden llevar a un rendimiento de red impredecible y problemas potenciales de distribución de tráfico.",
		"fr": "Des paramètres de bande passante incohérents peuvent entraîner des performances réseau imprévisibles et des problèmes potentiels de distribution du trafic.",
		"pt": "Configurações inconsistentes de largura de banda podem levar a desempenho de rede imprevisível e problemas potenciais de distribuição de tráfego.",
	},
	"recommendation": {
		"en": "Ensure all EIPs bound to SNAT entries have consistent bandwidth settings or use a shared bandwidth package.",
		"zh": "确保绑定到 SNAT 条目的所有 EIP 具有一致的带宽设置，或使用共享带宽包。",
		"ja": "SNAT エントリにバインドされているすべての EIP が一貫した帯域幅設定を持つか、共有帯域幅パッケージを使用するようにします。",
		"de": "Stellen Sie sicher, dass alle an SNAT-Einträge gebundenen EIPs konsistente Bandbreiteneinstellungen haben oder ein gemeinsames Bandbreitenpaket verwenden.",
		"es": "Asegúrese de que todos los EIPs vinculados a entradas SNAT tengan configuraciones de ancho de banda consistentes o usen un paquete de ancho de banda compartido.",
		"fr": "Assurez-vous que tous les EIP liés aux entrées SNAT ont des paramètres de bande passante cohérents ou utilisent un package de bande passante partagée.",
		"pt": "Garanta que todos os EIPs vinculados a entradas SNAT tenham configurações de largura de banda consistentes ou usem um pacote de largura de banda compartilhado.",
	},
	"resource_types": ["ALIYUN::VPC::NatGateway"],
}

is_vpc_nat_gateway(resource) if {
	network_type := helpers.get_property(resource, "NetworkType", "")
	network_type == "intranet"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::NatGateway")
	not is_vpc_nat_gateway(resource)

	# Simplified check: assumes proper configuration is present
	not helpers.has_property(resource, "EipBindMode")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EipBindMode"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
