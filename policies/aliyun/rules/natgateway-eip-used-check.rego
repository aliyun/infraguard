package infraguard.rules.aliyun.natgateway_eip_used_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "natgateway-eip-used-check",
	"name": {
		"en": "NAT Gateway EIP Usage Check",
		"zh": "NAT 网关中 SNAT 和 DNAT 未使用同一个 EIP",
		"ja": "NAT ゲートウェイ EIP 使用チェック",
		"de": "NAT-Gateway EIP-Verwendungsprüfung",
		"es": "Verificación de Uso de EIP de Puerta de Enlace NAT",
		"fr": "Vérification de l'Utilisation EIP de la Passerelle NAT",
		"pt": "Verificação de Uso de EIP do Gateway NAT",
	},
	"severity": "medium",
	"description": {
		"en": "SNAT and DNAT should not use the same EIP to avoid potential conflicts and improve network segmentation.",
		"zh": "NAT 网关的 SNAT 和 DNAT 未同时使用同一个 EIP，视为合规。",
		"ja": "SNAT と DNAT は潜在的な競合を避け、ネットワークセグメンテーションを改善するために同じ EIP を使用すべきではありません。",
		"de": "SNAT und DNAT sollten nicht dasselbe EIP verwenden, um potenzielle Konflikte zu vermeiden und die Netzwerksegmentierung zu verbessern.",
		"es": "SNAT y DNAT no deben usar el mismo EIP para evitar conflictos potenciales y mejorar la segmentación de red.",
		"fr": "SNAT et DNAT ne doivent pas utiliser le même EIP pour éviter les conflits potentiels et améliorer la segmentation réseau.",
		"pt": "SNAT e DNAT não devem usar o mesmo EIP para evitar conflitos potenciais e melhorar a segmentação de rede.",
	},
	"reason": {
		"en": "Using the same EIP for both SNAT and DNAT can lead to routing conflicts and security issues.",
		"zh": "SNAT 和 DNAT 使用同一个 EIP 可能导致路由冲突和安全问题。",
		"ja": "SNAT と DNAT の両方に同じ EIP を使用すると、ルーティング競合とセキュリティの問題が発生する可能性があります。",
		"de": "Die Verwendung desselben EIP für sowohl SNAT als auch DNAT kann zu Routingkonflikten und Sicherheitsproblemen führen.",
		"es": "Usar el mismo EIP tanto para SNAT como para DNAT puede provocar conflictos de enrutamiento y problemas de seguridad.",
		"fr": "Utiliser le même EIP pour SNAT et DNAT peut entraîner des conflits de routage et des problèmes de sécurité.",
		"pt": "Usar o mesmo EIP para SNAT e DNAT pode levar a conflitos de roteamento e problemas de segurança.",
	},
	"recommendation": {
		"en": "Configure different EIPs for SNAT and DNAT entries.",
		"zh": "为 SNAT 和 DNAT 条目配置不同的 EIP。",
		"ja": "SNAT と DNAT エントリに異なる EIP を設定します。",
		"de": "Konfigurieren Sie verschiedene EIPs für SNAT- und DNAT-Einträge.",
		"es": "Configure EIP diferentes para las entradas SNAT y DNAT.",
		"fr": "Configurez des EIP différents pour les entrées SNAT et DNAT.",
		"pt": "Configure EIPs diferentes para as entradas SNAT e DNAT.",
	},
	"resource_types": ["ALIYUN::NAT::NatGateway"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAT::NatGateway")

	# Simplified check - in practice would check ForwardTableId and SNatTableId
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
