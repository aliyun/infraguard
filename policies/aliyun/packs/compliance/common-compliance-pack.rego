package infraguard.packs.aliyun.compliance

import rego.v1

pack_meta := {
	"id": "compliance",
	"name": {
		"en": "Cloud Compliance Pack",
		"zh": "云基础设施合规包",
		"ja": "クラウドコンプライアンスパック",
		"de": "Cloud-Compliance-Paket",
		"es": "Paquete de Cumplimiento Cloud",
		"fr": "Pack de Conformite Cloud",
		"pt": "Pacote de Conformidade Cloud"
	},
	"description": {
		"en": "Compliance-oriented InfraGuard policies for Alibaba Cloud ROS templates, covering deletion protection, log backup, access restriction, encryption, and resilient log storage.",
		"zh": "面向 Alibaba Cloud ROS 模板的合规策略组合，覆盖删除保护、日志备份、访问限制、加密和日志冗余存储。",
		"ja": "Alibaba Cloud ROS テンプレート向けのコンプライアンス重視 InfraGuard ポリシーで、削除保護、ログバックアップ、アクセス制限、暗号化、ログ冗長保存をカバーします。",
		"de": "Compliance-orientierte InfraGuard-Richtlinien fuer Alibaba Cloud ROS-Vorlagen, mit Loeschschutz, Log-Backup, Zugriffsbeschraenkung, Verschluesselung und redundantem Logspeicher.",
		"es": "Politicas de InfraGuard orientadas al cumplimiento para plantillas ROS de Alibaba Cloud, con proteccion contra eliminacion, copias de seguridad de logs, restriccion de acceso, cifrado y almacenamiento redundante de logs.",
		"fr": "Politiques InfraGuard orientees conformite pour les modeles ROS Alibaba Cloud, couvrant la protection contre la suppression, la sauvegarde des journaux, la restriction d'acces, le chiffrement et le stockage redondant des journaux.",
		"pt": "Politicas InfraGuard voltadas a conformidade para modelos ROS do Alibaba Cloud, cobrindo protecao contra exclusao, backup de logs, restricao de acesso, criptografia e armazenamento redundante de logs."
	},
	"rules": [
		"ecs-instance-deletion-protection-enabled",
		"maxcompute-project-encryption-enabled",
		"nas-filesystem-encrypt-type-check",
		"polardb-cluster-enabled-tde",
		"rds-instance-enabled-log-backup",
		"rds-white-list-internet-ip-access-check",
		"sls-project-multi-zone"
	]
}
