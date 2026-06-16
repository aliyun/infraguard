package infraguard.packs.aliyun.elasticity

import rego.v1

pack_meta := {
	"id": "elasticity",
	"name": {
		"en": "Elasticity Pack",
		"zh": "弹性能力合规包",
		"ja": "弾力性パック",
		"de": "Elastizitatspaket",
		"es": "Paquete de elasticidad",
		"fr": "Pack elasticite",
		"pt": "Pacote de elasticidade"
	},
	"description": {
		"en": "Checks Alibaba Cloud ROS resources for autoscaling limits, placement choices, launch capacity, scaling actions, load balancer health checks, serverless concurrency, and MSE capacity.",
		"zh": "检查阿里云 ROS 资源的自动伸缩边界、部署候选、启动容量、伸缩动作、负载均衡健康检查、Serverless 并发和 MSE 容量配置。",
		"ja": "Alibaba Cloud ROS リソースの自動スケーリング制限、配置候補、起動容量、スケーリングアクション、ロードバランサーヘルスチェック、サーバーレス同時実行、MSE 容量を確認します。",
		"de": "Prueft Alibaba Cloud ROS-Ressourcen auf Autoskalierungsgrenzen, Platzierungsoptionen, Startkapazitaet, Skalierungsaktionen, Load-Balancer-Health-Checks, serverlose Parallelitaet und MSE-Kapazitaet.",
		"es": "Comprueba recursos ROS de Alibaba Cloud para limites de autoescalado, opciones de ubicacion, capacidad de arranque, acciones de escalado, verificaciones de salud de balanceadores, concurrencia serverless y capacidad MSE.",
		"fr": "Verifie les ressources ROS Alibaba Cloud pour les limites d'autoscaling, les choix de placement, la capacite de lancement, les actions de scaling, les controles de sante des equilibreurs, la concurrence serverless et la capacite MSE.",
		"pt": "Verifica recursos ROS da Alibaba Cloud quanto a limites de autoescalonamento, opcoes de posicionamento, capacidade de lancamento, acoes de escala, verificacoes de saude de balanceadores, concorrencia serverless e capacidade MSE."
	},
	"rules": [
		"ack-cluster-node-pool-autoscaling-enabled",
		"ack-cluster-node-pool-scaling-limits-required",
		"alb-all-listener-health-check-enabled",
		"alb-all-listenter-has-server",
		"ess-group-health-check",
		"ess-scaling-configuration-image-check",
		"ess-scaling-configuration-instance-type-candidates-required",
		"ess-scaling-group-attach-multi-switch",
		"ess-scaling-group-capacity-bounds-required",
		"ess-scaling-group-cooldown-configured",
		"ess-scaling-rule-action-configured",
		"fc-function-instance-concurrency-configured",
		"fc-function-timeout-configured",
		"mse-cluster-high-availability-configured",
		"slb-all-listener-health-check-enabled"
	]
}
