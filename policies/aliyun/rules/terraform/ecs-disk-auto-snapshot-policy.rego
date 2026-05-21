package infraguard.rules.terraform.ecs_disk_auto_snapshot_policy

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-disk-auto-snapshot-policy",
	"severity": "low",
	"name": {
		"en": "ECS disk has auto snapshot policy configured",
		"zh": "ECS 磁盘设置自动快照策略",
		"ja": "ECS ディスクに自動スナップショットポリシーが設定されている",
		"de": "ECS-Disk hat automatische Snapshot-Richtlinie konfiguriert",
		"es": "Disco ECS tiene política de snapshot automático configurada",
		"fr": "Disque ECS a une politique de snapshot automatique configurée",
		"pt": "Disco ECS tem política de snapshot automático configurada"
	},
	"description": {
		"en": "ECS disk has auto snapshot policy configured, considered compliant.",
		"zh": "ECS 磁盘设置了自动快照策略，视为合规。",
		"ja": "ECS ディスクに自動スナップショットポリシーが設定されている場合、準拠と見なされます。使用中でないディスク、自動スナップショットポリシーをサポートしないディスク、ACK クラスタによってマウントされた非永続化ディスクは適用されません。自動スナップショットポリシーを有効にすると、Alibaba Cloud は事前設定された時間とサイクルに従ってクラウドディスクのスナップショットを自動的に作成し、ウイルス侵入やランサムウェア攻撃から迅速に回復できるようにします。",
		"de": "ECS-Disk hat automatische Snapshot-Richtlinie konfiguriert, wird als konform betrachtet. Nicht verwendete Disks, Disks, die keine automatische Snapshot-Richtlinie unterstützen, und nicht persistente Disks, die von ACK-Clustern gemountet werden, sind nicht anwendbar. Nach Aktivierung der automatischen Snapshot-Richtlinie erstellt Alibaba Cloud automatisch Snapshots für Cloud-Disks gemäß voreingestellten Zeitpunkten und Zyklen, was eine schnelle Wiederherstellung nach Virenbefall oder Ransomware-Angriffen ermöglicht.",
		"es": "El disco ECS tiene política de snapshot automático configurada, considerada conforme. Los discos no en uso, discos que no admiten política de snapshot automático y discos no persistentes montados por clústeres ACK no son aplicables. Después de habilitar la política de snapshot automático, Alibaba Cloud creará automáticamente snapshots para discos en la nube según puntos de tiempo y ciclos predefinidos, permitiendo recuperación rápida de intrusión de virus o ataques de ransomware.",
		"fr": "Le disque ECS a une politique de snapshot automatique configurée, considérée comme conforme. Les disques non utilisés, les disques qui ne prennent pas en charge la politique de snapshot automatique et les disques non persistants montés par les clusters ACK ne sont pas applicables. Après avoir activé la politique de snapshot automatique, Alibaba Cloud créera automatiquement des snapshots pour les disques cloud selon les points de temps et cycles prédéfinis, permettant une récupération rapide après une intrusion de virus ou des attaques de ransomware.",
		"pt": "Disco ECS tem política de snapshot automático configurada, considerado conforme. Discos não em uso, discos que não suportam política de snapshot automático e discos não persistentes montados por clusters ACK não são aplicáveis. Após habilitar a política de snapshot automático, o Alibaba Cloud criará automaticamente snapshots para discos em nuvem de acordo com pontos de tempo e ciclos predefinidos, permitindo recuperação rápida de invasão de vírus ou ataques de ransomware."
	},
	"reason": {
		"en": "ECS disk does not have auto snapshot policy configured",
		"zh": "ECS 磁盘未设置自动快照策略",
		"ja": "ECS ディスクに自動スナップショットポリシーが設定されていません",
		"de": "ECS-Disk hat keine automatische Snapshot-Richtlinie konfiguriert",
		"es": "El disco ECS no tiene política de snapshot automático configurada",
		"fr": "Le disque ECS n'a pas de politique de snapshot automatique configurée",
		"pt": "Disco ECS não tem política de snapshot automático configurada"
	},
	"recommendation": {
		"en": "Configure an auto snapshot policy for ECS disks.",
		"zh": "为 ECS 磁盘配置自动快照策略。",
		"ja": "自動バックアップを有効にし、セキュリティインシデントから迅速に回復するために、ECS ディスクに自動スナップショットポリシーを設定します",
		"de": "Konfigurieren Sie eine automatische Snapshot-Richtlinie für ECS-Disks, um automatische Backups zu aktivieren und schnelle Wiederherstellung nach Sicherheitsvorfällen zu ermöglichen",
		"es": "Configure política de snapshot automático para disco ECS para habilitar backup automático y recuperación rápida de incidentes de seguridad",
		"fr": "Configurez une politique de snapshot automatique pour le disque ECS pour activer la sauvegarde automatique et la récupération rapide après des incidents de sécurité",
		"pt": "Configure política de snapshot automático para disco ECS para habilitar backup automático e recuperação rápida de incidentes de segurança"
	},
	"resource_types": ["alicloud_disk", "alicloud_ecs_auto_snapshot_policy_attachment", "alicloud_ecs_disk"],
	"iac_type": "terraform"
}

auto_snapshot_enabled(resource) if {
	tf.get_attribute(resource, "enable_auto_snapshot", false) == true
}

auto_snapshot_enabled(resource) if {
	tf.get_attribute(resource, "enable_auto_snapshot", "") == "true"
}

has_auto_snapshot_policy_attachment(name) if {
	some _, attachment in tf.resources_by_type("alicloud_ecs_auto_snapshot_policy_attachment")
	disk_id := tf.get_attribute(attachment, "disk_id", "")
	tf.is_unknown(disk_id)
}

has_auto_snapshot_policy_attachment(name) if {
	some _, attachment in tf.resources_by_type("alicloud_ecs_auto_snapshot_policy_attachment")
	disk_id := tf.get_attribute(attachment, "disk_id", "")
	not tf.is_unknown(disk_id)
	disk_id == name
}

has_auto_snapshot_policy_attachment(name) if {
	some _, attachment in tf.resources_by_type("alicloud_auto_snapshot_policy_attachment")
	disk_id := tf.get_attribute(attachment, "disk_id", "")
	tf.is_unknown(disk_id)
}

has_auto_snapshot_policy_attachment(name) if {
	some _, attachment in tf.resources_by_type("alicloud_auto_snapshot_policy_attachment")
	disk_id := tf.get_attribute(attachment, "disk_id", "")
	not tf.is_unknown(disk_id)
	disk_id == name
}

is_compliant(name, resource) if {
	auto_snapshot_enabled(resource)
}

is_compliant(name, resource) if {
	has_auto_snapshot_policy_attachment(name)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ecs_disk")
	not is_compliant(name, resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ecs_disk.%s", [name]),
		"violation_path": ["enable_auto_snapshot"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_disk")
	not is_compliant(name, resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_disk.%s", [name]),
		"violation_path": ["enable_auto_snapshot"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
