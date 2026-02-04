package infraguard.packs.aliyun.change_management_best_practice

import rego.v1

pack_meta := {
	"id": "change-management-best-practice",
	"name": {
		"en": "Change Management Best Practice",
		"zh": "变更管理最佳实践",
		"ja": "変更管理のベストプラクティス",
		"de": "Änderungsmanagement Best Practices",
		"es": "Mejores Prácticas de Gestión de Cambios",
		"fr": "Meilleures Pratiques de Gestion des Changements",
		"pt": "Melhores Práticas de Gestão de Mudanças",
	},
	"description": {
		"en": "From the change management dimension, detect the stability of cloud resources to help identify potential issues in advance and improve stability and operational efficiency.",
		"zh": "从变更管理维度,对云上资源的稳定性做检测,有助于提前发现隐患,提升稳定性和运维效率。",
		"ja": "変更管理の観点から、クラウドリソースの安定性を検出し、潜在的な問題を事前に特定し、安定性と運用効率を向上させます。",
		"de": "Aus der Perspektive des Änderungsmanagements die Stabilität von Cloud-Ressourcen erkennen, um potenzielle Probleme im Voraus zu identifizieren und die Stabilität und Betriebseffizienz zu verbessern.",
		"es": "Desde la dimensión de gestión de cambios, detectar la estabilidad de los recursos en la nube para ayudar a identificar problemas potenciales con anticipación y mejorar la estabilidad y la eficiencia operativa.",
		"fr": "Depuis la dimension de gestion des changements, détecter la stabilité des ressources cloud pour aider à identifier les problèmes potentiels à l'avance et améliorer la stabilité et l'efficacité opérationnelle.",
		"pt": "Da dimensão de gestão de mudanças, detectar a estabilidade dos recursos em nuvem para ajudar a identificar problemas potenciais com antecedência e melhorar a estabilidade e a eficiência operacional.",
	},
	"rules": [
		# "adb-cluster-maintain-time-check",  # Commented: ROS ADB::DBCluster does not support MaintainTime property
		"ecs-snapshot-policy-timepoints-check",
		"ecs-snapshot-retention-days",
		"polardb-cluster-maintain-time-check",
		"rds-instance-maintain-time-check",
		"redis-instance-backup-time-check",
	],
}
