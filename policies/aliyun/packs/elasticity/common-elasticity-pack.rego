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
		"en": "Elasticity scenario roll-up for Alibaba Cloud ROS resources, covering autoscaling limits, placement choices, launch capacity, scaling actions, load balancer health checks, serverless concurrency, and MSE capacity.",
		"zh": "阿里云弹性能力场景总包，覆盖 ROS 资源的自动伸缩边界、部署候选、启动容量、伸缩动作、负载均衡健康检查、Serverless 并发和 MSE 容量配置。",
		"ja": "Alibaba Cloud ROS リソース向けの弾力性シナリオ roll-up で、自動スケーリング制限、配置候補、起動容量、スケーリングアクション、ロードバランサーヘルスチェック、サーバーレス同時実行、MSE 容量を確認します。",
		"de": "Elastizitaets-Szenario-Roll-up fuer Alibaba Cloud ROS-Ressourcen mit Autoskalierungsgrenzen, Platzierungsoptionen, Startkapazitaet, Skalierungsaktionen, Load-Balancer-Health-Checks, serverloser Parallelitaet und MSE-Kapazitaet.",
		"es": "Roll-up de escenario de elasticidad para recursos ROS de Alibaba Cloud, con limites de autoescalado, opciones de ubicacion, capacidad de arranque, acciones de escalado, health checks de balanceadores, concurrencia serverless y capacidad MSE.",
		"fr": "Roll-up de scenario elasticite pour les ressources ROS Alibaba Cloud, couvrant limites d'autoscaling, choix de placement, capacite de lancement, actions de scaling, controles de sante des equilibreurs, concurrence serverless et capacite MSE.",
		"pt": "Roll-up de cenario de elasticidade para recursos ROS do Alibaba Cloud, cobrindo limites de autoescalonamento, opcoes de posicionamento, capacidade de lancamento, acoes de escala, health checks de balanceadores, concorrencia serverless e capacidade MSE."
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
