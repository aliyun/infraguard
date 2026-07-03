package infraguard.packs.aliyun.cost_optimization

import rego.v1

pack_meta := {
	"id": "cost-optimization",
	"name": {
		"en": "Cost Optimization Pack",
		"zh": "成本优化合规包",
		"ja": "コスト最適化パック",
		"de": "Kostenoptimierungspaket",
		"es": "Paquete de optimización de costos",
		"fr": "Pack d'optimisation des coûts",
		"pt": "Pacote de otimização de custos"
	},
	"description": {
		"en": "Directory roll-up of Alibaba Cloud cost optimization packs for sizing, idle-resource detection, retention, storage, database, cache, network, and log cost controls.",
		"zh": "阿里云成本优化目录级总包，汇总规格选型、闲置资源识别、保留周期、存储、数据库、缓存、网络和日志成本控制检查。",
		"ja": "Alibaba Cloud のコスト最適化 pack をディレクトリ単位で集約し、サイズ選択、アイドルリソース検出、保持期間、ストレージ、データベース、キャッシュ、ネットワーク、ログのコスト制御を確認します。",
		"de": "Directory-Roll-up der Alibaba-Cloud-Kostenoptimierungs-Packs fuer Sizing, Idle-Ressourcen, Aufbewahrung, Speicher, Datenbanken, Cache, Netzwerk und Log-Kostenkontrollen.",
		"es": "Roll-up de directorio de packs de optimizacion de costos de Alibaba Cloud para dimensionamiento, recursos inactivos, retencion, almacenamiento, bases de datos, cache, red y logs.",
		"fr": "Roll-up de repertoire des packs d'optimisation des couts Alibaba Cloud pour dimensionnement, ressources inactives, retention, stockage, bases de donnees, cache, reseau et journaux.",
		"pt": "Roll-up de diretorio dos packs de otimizacao de custos do Alibaba Cloud para dimensionamento, recursos ociosos, retencao, armazenamento, bancos de dados, cache, rede e logs."
	},
	"rules": [
		"ecs-disk-category-required",
		"ecs-disk-idle-check",
		"ecs-disk-size-required",
		"ecs-instance-bandwidth-configured",
		"ecs-instance-charge-type-required",
		"ecs-instance-type-required",
		"eip-bandwidth-required",
		"logstore-ttl-required",
		"nat-gateway-spec-required",
		"oss-storage-class-required",
		"rds-pay-type-required",
		"rds-storage-type-required",
		"redis-instance-class-required",
		"slb-internet-charge-type-required"
	]
}
