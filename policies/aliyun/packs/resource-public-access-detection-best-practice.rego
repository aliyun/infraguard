package infraguard.packs.aliyun.resource_public_access_detection_best_practice

import rego.v1

pack_meta := {
	"id": "resource-public-access-detection-best-practice",
	"name": {
		"en": "Resource Public Access Detection Best Practice",
		"zh": "资源开启公网检测最佳实践",
		"ja": "リソースパブリックアクセス検出のベストプラクティス",
		"de": "Ressourcen-Öffentlicher-Zugriff-Erkennung Best Practices",
		"es": "Mejores Prácticas de Detección de Acceso Público a Recursos",
		"fr": "Meilleures Pratiques de Détection d'Accès Public aux Ressources",
		"pt": "Melhores Práticas de Detecção de Acesso Público a Recursos",
	},
	"description": {
		"en": "Best practices for detecting and managing public access to cloud resources to ensure security.",
		"zh": "检测和管理云资源公网访问的最佳实践,确保安全性。",
		"ja": "セキュリティを確保するために、クラウドリソースへのパブリックアクセスを検出および管理するベストプラクティス。",
		"de": "Best Practices zur Erkennung und Verwaltung des öffentlichen Zugriffs auf Cloud-Ressourcen, um Sicherheit zu gewährleisten.",
		"es": "Mejores prácticas para detectar y gestionar el acceso público a recursos en la nube para garantizar la seguridad.",
		"fr": "Meilleures pratiques pour détecter et gérer l'accès public aux ressources cloud afin de garantir la sécurité.",
		"pt": "Melhores práticas para detectar e gerenciar acesso público a recursos em nuvem para garantir segurança.",
	},
	"rules": [
		"ack-cluster-public-endpoint-check",
		# "adb-public-access-check",  # Commented: ROS ADB::DBCluster does not support PublicEndpoint property
		# "kafka-instance-public-access-check",
		# "apigateway-ipv4-public-access-check",
		# "apigateway-ipv6-public-access-check",
		# "cr-instance-public-access-check",  # Commented: ROS CR::Instance does not support PublicNetworkAccess property
		"cr-repository-type-private",
		"ecs-running-instance-no-public-ip",
		"sg-public-access-check",
		"emr-cluster-master-public-access-check",
		"elasticsearch-public-and-any-ip-access-check",
		# "hbase-public-access-check",
		# "lindorm-instance-public-access-check",
		"mse-cluster-config-auth-enabled",
		"mongodb-public-and-any-ip-access-check",
		# "nas-access-group-public-access-check",
		# "ots-instance-network-not-normal",
		# "oceanbase-public-and-any-ip-access-check",
		"polardb-public-and-any-ip-access-check",
		"rds-public-access-check",
		"redis-public-and-any-ip-access-check",
		# "tsdb-instance-public-access-check",
	],
}
