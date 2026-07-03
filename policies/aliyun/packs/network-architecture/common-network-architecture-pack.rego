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
		"en": "Directory roll-up of Alibaba Cloud network architecture packs for VPC planning, zone placement, private exposure, load balancer topology, and enterprise network hub attachments.",
		"zh": "阿里云网络架构目录级总包，汇总 VPC 规划、可用区落点、私网暴露、负载均衡拓扑和企业网络枢纽连接相关检查。",
		"ja": "Alibaba Cloud のネットワークアーキテクチャ pack をディレクトリ単位で集約し、VPC 計画、ゾーン配置、プライベート公開、ロードバランサートポロジー、エンタープライズネットワークハブ接続を確認します。",
		"de": "Directory-Roll-up der Alibaba-Cloud-Netzwerkarchitektur-Packs fuer VPC-Planung, Zonenplatzierung, private Exposition, Load-Balancer-Topologie und Enterprise-Netzwerk-Hub-Anbindungen.",
		"es": "Roll-up de directorio de packs de arquitectura de red de Alibaba Cloud para planificacion VPC, ubicacion por zonas, exposicion privada, topologia de balanceadores y hubs de red empresariales.",
		"fr": "Roll-up de repertoire des packs d'architecture reseau Alibaba Cloud pour planification VPC, placement par zone, exposition privee, topologie des equilibreurs et hubs reseau d'entreprise.",
		"pt": "Roll-up de diretorio dos packs de arquitetura de rede do Alibaba Cloud para planejamento VPC, posicionamento por zona, exposicao privada, topologia de balanceadores e hubs de rede empresariais."
	},
	"rules": [
		"alb-address-type-check",
		"alb-address-type-intranet",
		"alb-all-listener-health-check-enabled",
		"cen-instance-name-required",
		"eip-explicit-bandwidth-required",
		"nat-gateway-vpc-required",
		"nlb-address-type-intranet",
		"security-group-enterprise-type",
		"security-group-vpc-required",
		"slb-acl-public-access-check",
		"slb-address-type-intranet",
		"slb-all-listener-health-check-enabled",
		"slb-all-listener-servers-multi-zone",
		"slb-all-listenter-tls-policy-check",
		"slb-delete-protection-enabled",
		"slb-instance-loadbalancerspec-check",
		"slb-instance-multi-zone",
		"slb-listener-https-enabled",
		"slb-modify-protection-check",
		"transit-router-vpc-attachment-multi-zone",
		"vpc-cidr-required",
		"vpn-gateway-vpc-required",
		"vswitch-cidr-required",
		"vswitch-zone-required"
	]
}
