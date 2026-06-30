package infraguard.packs.aliyun.ros_best_practice

import rego.v1

pack_meta := {
	"id": "ros-best-practice",
	"name": {
		"en": "ROS Best Practice Pack",
		"zh": "ROS 最佳实践合规包",
		"ja": "ROS ベストプラクティスパック",
		"de": "ROS Best Practices Paket",
		"es": "Paquete de Mejores Prácticas ROS",
		"fr": "Pack de Meilleures Pratiques ROS",
		"pt": "Pacote de Melhores Práticas ROS"
	},
	"description": {
		"en": "A compliance pack covering ROS template best practices, including metadata configuration and sensitive parameter protection.",
		"zh": "涵盖 ROS 模板最佳实践的合规包，包括元数据配置和敏感参数保护等。",
		"ja": "メタデータ設定や機密パラメータ保護を含む ROS テンプレートのベストプラクティスをカバーするコンプライアンスパック。",
		"de": "Ein Compliance-Paket, das ROS-Vorlagen-Best-Practices abdeckt, einschließlich Metadaten-Konfiguration und Schutz sensibler Parameter.",
		"es": "Un paquete de cumplimiento que cubre las mejores prácticas de plantillas ROS, incluyendo configuración de metadatos y protección de parámetros sensibles.",
		"fr": "Un pack de conformité couvrant les meilleures pratiques des modèles ROS, incluant la configuration des métadonnées et la protection des paramètres sensibles.",
		"pt": "Um pacote de conformidade cobrindo as melhores práticas de templates ROS, incluindo configuração de metadados e proteção de parâmetros sensíveis."
	},
	"rules": [
		"metadata-ros-composer-check",
		"parameter-sensitive-noecho-check"
	]
}
