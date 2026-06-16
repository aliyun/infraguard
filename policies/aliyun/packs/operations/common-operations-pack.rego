package infraguard.packs.aliyun.operations

import rego.v1

pack_meta := {
	"id": "operations",
	"name": {
		"en": "Operations Pack",
		"zh": "可运维性合规包",
		"ja": "運用パック",
		"de": "Betriebspaket",
		"es": "Paquete de Operaciones",
		"fr": "Pack Opérations",
		"pt": "Pacote de Operações"
	},
	"description": {
		"en": "InfraGuard policies for observability, audit logging, backup, recovery, and deletion protection in Alibaba Cloud ROS templates.",
		"zh": "面向 Alibaba Cloud ROS 模板的 InfraGuard 策略，覆盖可观测、审计日志、备份恢复和删除保护。",
		"ja": "Alibaba Cloud ROS テンプレート向けに、可観測性、監査ログ、バックアップ、復旧、削除保護を確認する InfraGuard ポリシーです。",
		"de": "InfraGuard-Richtlinien fuer Observability, Audit-Logging, Backup, Wiederherstellung und Loeschschutz in Alibaba Cloud ROS-Templates.",
		"es": "Políticas de InfraGuard para observabilidad, registros de auditoría, backup, recuperación y protección contra eliminación en plantillas ROS de Alibaba Cloud.",
		"fr": "Politiques InfraGuard pour observabilite, journaux d'audit, sauvegarde, restauration et protection contre la suppression dans les modeles ROS Alibaba Cloud.",
		"pt": "Políticas InfraGuard para observabilidade, logs de auditoria, backup, recuperação e proteção contra exclusão em modelos ROS do Alibaba Cloud."
	},
	"rules": [
		"actiontrail-trail-name-required",
		"cms-alarm-name-required",
		"ecs-disk-auto-snapshot-policy",
		"ecs-instance-operational-deletion-protection",
		"fc-service-log-enable",
		"fc-service-tracing-enable",
		"oss-bucket-operational-access-logging",
		"polardb-cluster-delete-protection-enabled",
		"rds-backup-policy-required",
		"rds-instance-deletion-protection-enabled",
		"redis-backup-policy-required",
		"sls-logstore-shard-count-configured",
		"sls-logstore-ttl-configured"
	]
}
