package infraguard.packs.aliyun.slb_application_best_practice

import rego.v1

pack_meta := {
	"id": "slb-application-best-practice",
	"name": {
		"en": "SLB Application Best Practice",
		"zh": "负载均衡应用最佳实践",
		"ja": "SLB アプリケーションのベストプラクティス",
		"de": "SLB-Anwendung Best Practices",
		"es": "Mejores Prácticas de Aplicación SLB",
		"fr": "Meilleures Pratiques d'Application SLB",
		"pt": "Melhores Práticas de Aplicação SLB"
	},
	"description": {
		"en": "Best practices for SLB and ALB configuration, covering high availability, security, health checks, and operational settings.",
		"zh": "SLB 和 ALB 配置最佳实践,涵盖高可用、安全、健康检查和运维设置。",
		"ja": "高可用性、セキュリティ、ヘルスチェック、運用設定をカバーする SLB および ALB 設定のベストプラクティス。",
		"de": "Best Practices für SLB- und ALB-Konfiguration, einschließlich Hochverfügbarkeit, Sicherheit, Health Checks und Betriebseinstellungen.",
		"es": "Mejores prácticas para la configuración de SLB y ALB, que cubren alta disponibilidad, seguridad, verificaciones de salud y configuraciones operativas.",
		"fr": "Meilleures pratiques pour la configuration SLB et ALB, couvrant la haute disponibilité, la sécurité, les contrôles de santé et les paramètres opérationnels.",
		"pt": "Melhores práticas para configuração SLB e ALB, cobrindo alta disponibilidade, segurança, verificações de saúde e configurações operacionais."
	},
	"rules": [
		# "alb-acl-has-specified-ip",
		"alb-address-type-check",
		# "alb-all-listener-enabled-acl",  # Commented: ROS ALB::Listener does not support AclConfig property,
		"alb-all-listener-health-check-enabled",
		# "alb-instance-idle-check",
		# "slb-acl-has-specified-ip",
		"slb-acl-public-access-check",
		"slb-all-listener-health-check-enabled",
		"slb-all-listener-servers-multi-zone",
		"slb-all-listenter-tls-policy-check",
		"slb-delete-protection-enabled",
		# "slb-instance-autorenewal-check",
		# "slb-instance-expired-check",
		# "slb-instance-idle-check",
		# "slb-instance-listener-count-check",
		"slb-instance-loadbalancerspec-check",
		"slb-instance-multi-zone",
		# "slb-listener-connection-drain-enabled",
		# "slb-listener-gzip-enabled",
		# "slb-listener-health-check-interval-check",
		# "slb-listener-health-check-threshold-check",
		# "slb-listener-health-check-timeout-check",
		# "slb-listener-http2-enabled",
		"slb-listener-https-enabled",
		"slb-modify-protection-check"
	]
}
