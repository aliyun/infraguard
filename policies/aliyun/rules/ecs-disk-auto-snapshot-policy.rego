package infraguard.rules.aliyun.ecs_disk_auto_snapshot_policy

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-disk-auto-snapshot-policy",
	"name": {
		"en": "ECS disk has auto snapshot policy configured",
		"zh": "ECS 磁盘设置自动快照策略",
		"ja": "ECS ディスクに自動スナップショットポリシーが設定されている",
		"de": "ECS-Disk hat automatische Snapshot-Richtlinie konfiguriert",
		"es": "Disco ECS tiene política de snapshot automático configurada",
		"fr": "Disque ECS a une politique de snapshot automatique configurée",
		"pt": "Disco ECS tem política de snapshot automático configurada",
	},
	"description": {
		"en": "ECS disk has auto snapshot policy configured, considered compliant. Disks not in use, disks that do not support auto snapshot policy, and non-persistent disks mounted by ACK clusters are not applicable. After enabling auto snapshot policy, Alibaba Cloud will automatically create snapshots for cloud disks according to preset time points and cycles, enabling quick recovery from virus intrusion or ransomware attacks.",
		"zh": "ECS 磁盘设置了自动快照策略,视为合规。状态非使用中的磁盘、不支持设置自动快照策略的磁盘、ACK 集群挂载的非持久化使用场景的磁盘视为不适用。开启自动快照策略后,阿里云会自动按照预设的时间点和周期为云盘创建快照,遭遇病毒入侵或勒索后能够快速从安全事件中恢复。",
		"ja": "ECS ディスクに自動スナップショットポリシーが設定されている場合、準拠と見なされます。使用中でないディスク、自動スナップショットポリシーをサポートしないディスク、ACK クラスタによってマウントされた非永続化ディスクは適用されません。自動スナップショットポリシーを有効にすると、Alibaba Cloud は事前設定された時間とサイクルに従ってクラウドディスクのスナップショットを自動的に作成し、ウイルス侵入やランサムウェア攻撃から迅速に回復できるようにします。",
		"de": "ECS-Disk hat automatische Snapshot-Richtlinie konfiguriert, wird als konform betrachtet. Nicht verwendete Disks, Disks, die keine automatische Snapshot-Richtlinie unterstützen, und nicht persistente Disks, die von ACK-Clustern gemountet werden, sind nicht anwendbar. Nach Aktivierung der automatischen Snapshot-Richtlinie erstellt Alibaba Cloud automatisch Snapshots für Cloud-Disks gemäß voreingestellten Zeitpunkten und Zyklen, was eine schnelle Wiederherstellung nach Virenbefall oder Ransomware-Angriffen ermöglicht.",
		"es": "El disco ECS tiene política de snapshot automático configurada, considerada conforme. Los discos no en uso, discos que no admiten política de snapshot automático y discos no persistentes montados por clústeres ACK no son aplicables. Después de habilitar la política de snapshot automático, Alibaba Cloud creará automáticamente snapshots para discos en la nube según puntos de tiempo y ciclos predefinidos, permitiendo recuperación rápida de intrusión de virus o ataques de ransomware.",
		"fr": "Le disque ECS a une politique de snapshot automatique configurée, considérée comme conforme. Les disques non utilisés, les disques qui ne prennent pas en charge la politique de snapshot automatique et les disques non persistants montés par les clusters ACK ne sont pas applicables. Après avoir activé la politique de snapshot automatique, Alibaba Cloud créera automatiquement des snapshots pour les disques cloud selon les points de temps et cycles prédéfinis, permettant une récupération rapide après une intrusion de virus ou des attaques de ransomware.",
		"pt": "Disco ECS tem política de snapshot automático configurada, considerado conforme. Discos não em uso, discos que não suportam política de snapshot automático e discos não persistentes montados por clusters ACK não são aplicáveis. Após habilitar a política de snapshot automático, o Alibaba Cloud criará automaticamente snapshots para discos em nuvem de acordo com pontos de tempo e ciclos predefinidos, permitindo recuperação rápida de invasão de vírus ou ataques de ransomware.",
	},
	"severity": "low",
	"resource_types": ["ALIYUN::ECS::Disk"],
	"reason": {
		"en": "ECS disk does not have auto snapshot policy configured",
		"zh": "ECS 磁盘未设置自动快照策略",
		"ja": "ECS ディスクに自動スナップショットポリシーが設定されていません",
		"de": "ECS-Disk hat keine automatische Snapshot-Richtlinie konfiguriert",
		"es": "El disco ECS no tiene política de snapshot automático configurada",
		"fr": "Le disque ECS n'a pas de politique de snapshot automatique configurée",
		"pt": "Disco ECS não tem política de snapshot automático configurada",
	},
	"recommendation": {
		"en": "Configure auto snapshot policy for ECS disk to enable automatic backup and quick recovery from security incidents",
		"zh": "为 ECS 磁盘配置自动快照策略以启用自动备份并快速从安全事件中恢复",
		"ja": "自動バックアップを有効にし、セキュリティインシデントから迅速に回復するために、ECS ディスクに自動スナップショットポリシーを設定します",
		"de": "Konfigurieren Sie eine automatische Snapshot-Richtlinie für ECS-Disks, um automatische Backups zu aktivieren und schnelle Wiederherstellung nach Sicherheitsvorfällen zu ermöglichen",
		"es": "Configure política de snapshot automático para disco ECS para habilitar backup automático y recuperación rápida de incidentes de seguridad",
		"fr": "Configurez une politique de snapshot automatique pour le disque ECS pour activer la sauvegarde automatique et la récupération rapide après des incidents de sécurité",
		"pt": "Configure política de snapshot automático para disco ECS para habilitar backup automático e recuperação rápida de incidentes de segurança",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")

	# Check if AutoSnapshotPolicyId is configured
	not helpers.has_property(resource, "AutoSnapshotPolicyId")

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
