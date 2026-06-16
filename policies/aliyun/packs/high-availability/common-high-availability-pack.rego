package infraguard.packs.aliyun.high_availability

import rego.v1

pack_meta := {
	"id": "high-availability",
	"name": {
		"en": "High Availability Pack",
		"zh": "高可用合规包",
		"ja": "高可用性パック",
		"de": "Hochverfügbarkeitspaket",
		"es": "Paquete de alta disponibilidad",
		"fr": "Pack haute disponibilité",
		"pt": "Pacote de alta disponibilidade"
	},
	"description": {
		"en": "Checks Alibaba Cloud ROS resources for multi-zone placement, load balancer failover, baseline replica counts, and zone-redundant storage.",
		"zh": "检查阿里云 ROS 资源的多可用区部署、负载均衡故障转移、基线副本数和同城冗余存储配置。",
		"ja": "Alibaba Cloud ROS リソースのマルチゾーン配置、ロードバランサーフェイルオーバー、基準レプリカ数、ゾーン冗長ストレージを確認します。",
		"de": "Prüft Alibaba Cloud ROS-Ressourcen auf Multi-Zone-Platzierung, Load-Balancer-Failover, Basis-Replikatanzahlen und zonenredundanten Speicher.",
		"es": "Comprueba recursos ROS de Alibaba Cloud para ubicación multi-zona, failover de balanceadores, recuentos base de réplicas y almacenamiento redundante por zona.",
		"fr": "Vérifie les ressources ROS Alibaba Cloud pour le placement multi-zone, le basculement des équilibreurs, les nombres de réplicas de base et le stockage redondant par zone.",
		"pt": "Verifica recursos ROS da Alibaba Cloud quanto a posicionamento multi-zona, failover de balanceadores, contagens base de réplicas e armazenamento redundante por zona."
	},
	"rules": [
		"alb-instance-multi-zone",
		"ecs-instance-group-max-amount-required",
		"ecs-instance-group-min-amount-required",
		"ess-scaling-group-multi-vswitch-distribution",
		"mongodb-instance-multi-zone",
		"nlb-loadbalancer-multi-zone",
		"oss-zrs-enabled",
		"polardb-cluster-multi-zone",
		"rds-instance-secondary-zone-required",
		"rds-instance-zone-required",
		"redis-instance-multi-zone",
		"slb-instance-master-zone-required",
		"slb-instance-multi-zone"
	]
}
