package infraguard.packs.aliyun.resource_expiration_notification_best_practice

import rego.v1

pack_meta := {
	"id": "resource-expiration-notification-best-practice",
	"name": {
		"en": "Resource Expiration Notification Best Practice",
		"zh": "资源到期提醒最佳实践",
		"ja": "リソース有効期限通知のベストプラクティス",
		"de": "Ressourcen-Ablaufbenachrichtigung Best Practices",
		"es": "Mejores Prácticas de Notificación de Expiración de Recursos",
		"fr": "Meilleures Pratiques de Notification d'Expiration des Ressources",
		"pt": "Melhores Práticas de Notificação de Expiração de Recursos",
	},
	"description": {
		"en": "Detects stability risks related to resource expiration, helping to discover hidden dangers in advance and improve stability and operational efficiency.",
		"zh": "从到期风险维度，对云上资源的稳定性做检测，有助于提前发现隐患，提升稳定性和运维效率。",
		"ja": "リソースの有効期限に関連する安定性リスクを検出し、潜在的な問題を事前に発見し、安定性と運用効率を向上させます。",
		"de": "Erkennt Stabilitätsrisiken im Zusammenhang mit dem Ablauf von Ressourcen und hilft, versteckte Gefahren im Voraus zu entdecken und die Stabilität und Betriebseffizienz zu verbessern.",
		"es": "Detecta riesgos de estabilidad relacionados con la expiración de recursos, ayudando a descubrir peligros ocultos con anticipación y mejorar la estabilidad y la eficiencia operativa.",
		"fr": "Détecte les risques de stabilité liés à l'expiration des ressources, aidant à découvrir les dangers cachés à l'avance et à améliorer la stabilité et l'efficacité opérationnelle.",
		"pt": "Detecta riscos de estabilidade relacionados à expiração de recursos, ajudando a descobrir perigos ocultos com antecedência e melhorar a estabilidade e a eficiência operacional.",
	},
	"rules": [
		# "adb-cluster-expired-check",
		"bastionhost-instance-expired-check",
		# "polardb-x1-instance-expired-check",
		# "polardb-x2-instance-expired-check",
		"ecs-instance-expired-check",
		# "eip-address-expired-check",
		"hbase-cluster-expired-check",
		"mongodb-cluster-expired-check",
		"polardb-cluster-expired-check",
		"rds-instance-expired-check",
		"redis-instance-expired-check",
		# "slb-instance-expired-check",
	],
}
