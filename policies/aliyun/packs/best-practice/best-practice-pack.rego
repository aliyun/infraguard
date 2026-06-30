package infraguard.packs.aliyun.best_practice

import rego.v1

pack_meta := {
	"id": "best-practice",
	"name": {
		"en": "Best Practice Pack",
		"zh": "最佳实践合规包",
		"ja": "ベストプラクティスパック",
		"de": "Best Practices Paket",
		"es": "Paquete de mejores prácticas",
		"fr": "Pack de meilleures pratiques",
		"pt": "Pacote de melhores práticas"
	},
	"description": {
		"en": "Best practice checks for resource names, tags, and descriptions in Alibaba Cloud ROS templates.",
		"zh": "面向 Alibaba Cloud ROS 模板的资源名称、标签和描述最佳实践检查。",
		"ja": "Alibaba Cloud ROS テンプレートにおけるリソース名、タグ、説明のベストプラクティスチェック。",
		"de": "Best-Practice-Prüfungen für Ressourcennamen, Tags und Beschreibungen in Alibaba Cloud ROS-Vorlagen.",
		"es": "Comprobaciones de mejores prácticas para nombres, etiquetas y descripciones de recursos en plantillas ROS de Alibaba Cloud.",
		"fr": "Contrôles de meilleures pratiques pour les noms, étiquettes et descriptions des ressources dans les modèles ROS Alibaba Cloud.",
		"pt": "Verificações de melhores práticas para nomes, tags e descrições de recursos em templates ROS da Alibaba Cloud."
	},
	"rules": [
		"alb-loadbalancer-name-required",
		"ecs-instance-name-required",
		"ecs-instance-tags-required",
		"ecs-security-group-description-required",
		"kms-key-description-required",
		"oss-bucket-tags-required",
		"polardb-cluster-tags-required",
		"rds-instance-tags-required",
		"redis-instance-name-required",
		"slb-loadbalancer-name-required",
		"sls-project-description-required",
		"vpc-name-required",
		"vswitch-name-required"
	]
}
