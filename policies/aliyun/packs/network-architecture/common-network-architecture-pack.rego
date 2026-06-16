package infraguard.packs.aliyun.network_architecture

import rego.v1

pack_meta := {
	"id": "network-architecture",
	"name": {
		"en": "Network Architecture Pack",
		"zh": "网络架构合规包",
		"ja": "ネットワークアーキテクチャパック",
		"de": "Netzwerkarchitektur-Paket",
		"es": "Paquete de Arquitectura de Red",
		"fr": "Pack Architecture Réseau",
		"pt": "Pacote de Arquitetura de Rede"
	},
	"description": {
		"en": "InfraGuard policies for VPC address planning, zone placement, private network exposure, and enterprise network hub attachments.",
		"zh": "覆盖 VPC 地址规划、可用区落点、私网暴露控制和企业网络枢纽连接的 InfraGuard 策略组合。",
		"ja": "VPC アドレス計画、ゾーン配置、プライベートネットワーク公開、エンタープライズネットワークハブ接続のための InfraGuard ポリシーです。",
		"de": "InfraGuard-Richtlinien für VPC-Adressplanung, Zonenplatzierung, private Netzwerkexposition und Unternehmensnetzwerk-Hub-Anbindungen.",
		"es": "Políticas de InfraGuard para planificación de direcciones VPC, ubicación por zonas, exposición de red privada y conexiones a hubs de red empresariales.",
		"fr": "Politiques InfraGuard pour la planification d'adresses VPC, le placement par zone, l'exposition réseau privée et les connexions aux hubs réseau d'entreprise.",
		"pt": "Políticas InfraGuard para planejamento de endereços VPC, posicionamento por zona, exposição de rede privada e conexões a hubs de rede empresariais."
	},
	"rules": [
		"alb-address-type-intranet",
		"cen-instance-name-required",
		"eip-explicit-bandwidth-required",
		"nat-gateway-vpc-required",
		"nlb-address-type-intranet",
		"security-group-enterprise-type",
		"security-group-vpc-required",
		"slb-address-type-intranet",
		"transit-router-vpc-attachment-multi-zone",
		"vpc-cidr-required",
		"vpn-gateway-vpc-required",
		"vswitch-cidr-required",
		"vswitch-zone-required"
	]
}
