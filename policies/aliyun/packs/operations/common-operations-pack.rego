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
		"en": "Directory roll-up of Alibaba Cloud operations packs for observability, audit logging, backup, recovery, lifecycle, expiration, change management, and deletion protection.",
		"zh": "阿里云可运维性目录级总包，汇总可观测、审计日志、备份恢复、生命周期、到期、变更管理和删除保护相关检查。",
		"ja": "Alibaba Cloud の運用 pack をディレクトリ単位で集約し、可観測性、監査ログ、バックアップ、復旧、ライフサイクル、期限、変更管理、削除保護を確認します。",
		"de": "Directory-Roll-up der Alibaba-Cloud-Operations-Packs fuer Observability, Audit-Logging, Backup, Recovery, Lifecycle, Ablauf, Change Management und Loeschschutz.",
		"es": "Roll-up de directorio de packs de operaciones de Alibaba Cloud para observabilidad, auditoria, backup, recuperacion, ciclo de vida, vencimiento, gestion de cambios y proteccion contra eliminacion.",
		"fr": "Roll-up de repertoire des packs d'operations Alibaba Cloud pour observabilite, audit, sauvegarde, restauration, cycle de vie, expiration, gestion des changements et protection contre la suppression.",
		"pt": "Roll-up de diretorio dos packs de operacoes do Alibaba Cloud para observabilidade, auditoria, backup, recuperacao, ciclo de vida, expiracao, gestao de mudancas e protecao contra exclusao."
	},
	"rules": [
		"actiontrail-trail-name-required",
		"alb-delete-protection-enabled",
		"bastionhost-instance-expired-check",
		"cms-alarm-name-required",
		"ecs-disk-auto-snapshot-policy",
		"ecs-instance-deletion-protection-enabled",
		"ecs-instance-enabled-security-protection",
		"ecs-instance-expired-check",
		"ecs-instance-operational-deletion-protection",
		"ecs-snapshot-policy-timepoints-check",
		"ecs-snapshot-retention-days",
		"eip-delete-protection-enabled",
		"fc-service-log-enable",
		"fc-service-tracing-enable",
		"hbase-cluster-deletion-protection",
		"hbase-cluster-expired-check",
		"kms-key-delete-protection-enabled",
		"mongodb-cluster-expired-check",
		"mongodb-instance-release-protection",
		"natgateway-delete-protection-enabled",
		"oss-bucket-operational-access-logging",
		"oss-bucket-versioning-enabled",
		"polardb-cluster-delete-protection-enabled",
		"polardb-cluster-expired-check",
		"polardb-cluster-maintain-time-check",
		"rds-backup-policy-required",
		"rds-instacne-delete-protection-enabled",
		"rds-instance-deletion-protection-enabled",
		"rds-instance-enabled-log-backup",
		"rds-instance-expired-check",
		"rds-instance-maintain-time-check",
		"redis-backup-policy-required",
		"redis-instance-backup-log-enabled",
		"redis-instance-backup-time-check",
		"redis-instance-expired-check",
		"redis-instance-release-protection",
		"slb-delete-protection-enabled",
		"slb-modify-protection-check",
		"sls-logstore-shard-count-configured",
		"sls-logstore-ttl-configured"
	]
}
