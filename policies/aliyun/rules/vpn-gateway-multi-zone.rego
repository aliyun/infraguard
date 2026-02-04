package infraguard.rules.aliyun.vpn_gateway_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "vpn-gateway-multi-zone",
	"name": {
		"en": "VPN Gateway Multi-Zone Deployment",
		"zh": "使用多可用区的 VPN 网关",
		"ja": "VPN ゲートウェイマルチゾーン展開",
		"de": "VPN-Gateway Multi-Zonen-Bereitstellung",
		"es": "Implementación Multi-Zona de Puerta de Enlace VPN",
		"fr": "Déploiement Multi-Zone de la Passerelle VPN",
		"pt": "Implantação Multi-Zona do Gateway VPN",
	},
	"severity": "medium",
	"description": {
		"en": "VPN Gateways should be configured with a disaster recovery VSwitch to support multi-zone availability.",
		"zh": "为 VPN 网关设置两个交换机，保障产品跨可用区的高可用性，视为合规。",
		"ja": "VPN ゲートウェイは、マルチゾーン可用性をサポートするために災害復旧 VSwitch で構成する必要があります。",
		"de": "VPN-Gateways sollten mit einem Disaster-Recovery-VSwitch konfiguriert werden, um Multi-Zonen-Verfügbarkeit zu unterstützen.",
		"es": "Las puertas de enlace VPN deben configurarse con un VSwitch de recuperación ante desastres para admitir disponibilidad multi-zona.",
		"fr": "Les passerelles VPN doivent être configurées avec un VSwitch de récupération d'urgence pour prendre en charge la disponibilité multi-zone.",
		"pt": "Os gateways VPN devem ser configurados com um VSwitch de recuperação de desastres para suportar disponibilidade multi-zona.",
	},
	"reason": {
		"en": "The VPN Gateway is not configured with a disaster recovery VSwitch.",
		"zh": "VPN 网关未配置容灾交换机。",
		"ja": "VPN ゲートウェイが災害復旧 VSwitch で構成されていません。",
		"de": "Das VPN-Gateway ist nicht mit einem Disaster-Recovery-VSwitch konfiguriert.",
		"es": "La puerta de enlace VPN no está configurada con un VSwitch de recuperación ante desastres.",
		"fr": "La passerelle VPN n'est pas configurée avec un VSwitch de récupération d'urgence.",
		"pt": "O gateway VPN não está configurado com um VSwitch de recuperação de desastres.",
	},
	"recommendation": {
		"en": "Configure DisasterRecoveryVSwitchId to enable dual-tunnel/multi-zone mode.",
		"zh": "配置 DisasterRecoveryVSwitchId 以启用双隧道/多可用区模式。",
		"ja": "デュアルトンネル/マルチゾーンモードを有効にするために DisasterRecoveryVSwitchId を設定します。",
		"de": "Konfigurieren Sie DisasterRecoveryVSwitchId, um den Dual-Tunnel/Multi-Zonen-Modus zu aktivieren.",
		"es": "Configure DisasterRecoveryVSwitchId para habilitar el modo de túnel dual/multi-zona.",
		"fr": "Configurez DisasterRecoveryVSwitchId pour activer le mode tunnel double/multi-zone.",
		"pt": "Configure DisasterRecoveryVSwitchId para habilitar o modo de túnel duplo/multi-zona.",
	},
	"resource_types": ["ALIYUN::VPC::VpnGateway"],
}

# Check if instance is multi-zone
is_multi_zone(resource) if {
	# Check if DisasterRecoveryVSwitchId is present and not empty
	object.get(resource.Properties, "DisasterRecoveryVSwitchId", "") != ""
}

# Deny rule
deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_multi_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DisasterRecoveryVSwitchId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
