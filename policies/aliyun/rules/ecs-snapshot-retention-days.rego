package infraguard.rules.aliyun.ecs_snapshot_retention_days

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-snapshot-retention-days",
	"name": {
		"en": "ECS auto snapshot retention days meets requirements",
		"zh": "ECS 自动快照保留天数满足指定要求",
		"ja": "ECS 自動スナップショットの保持日数が要件を満たしている",
		"de": "ECS automatische Snapshot-Aufbewahrungstage erfüllen Anforderungen",
		"es": "Días de retención de snapshot automático ECS cumplen requisitos",
		"fr": "Jours de rétention de snapshot automatique ECS répondent aux exigences",
		"pt": "Dias de retenção de snapshot automático ECS atendem requisitos",
	},
	"description": {
		"en": "ECS auto snapshot policy retention days is greater than the specified number of days, considered compliant. Default value: 7 days.",
		"zh": "ECS 自动快照策略设置快照保留天数大于设置的天数,视为合规。默认值:7 天。",
		"ja": "ECS 自動スナップショットポリシーの保持日数が指定された日数を超えている場合、準拠と見なされます。デフォルト値: 7 日。",
		"de": "ECS automatische Snapshot-Richtlinie Aufbewahrungstage ist größer als die angegebene Anzahl von Tagen, wird als konform betrachtet. Standardwert: 7 Tage.",
		"es": "Los días de retención de la política de snapshot automático ECS son mayores que el número especificado de días, considerado conforme. Valor predeterminado: 7 días.",
		"fr": "Les jours de rétention de la politique de snapshot automatique ECS sont supérieurs au nombre de jours spécifié, considéré comme conforme. Valeur par défaut: 7 jours.",
		"pt": "Os dias de retenção da política de snapshot automático ECS são maiores que o número especificado de dias, considerado conforme. Valor padrão: 7 dias.",
	},
	"severity": "low",
	"resource_types": ["ALIYUN::ECS::AutoSnapshotPolicy"],
	"reason": {
		"en": "Auto snapshot retention days is less than the minimum required days (7 days)",
		"zh": "自动快照保留天数少于最低要求天数(7 天)",
		"ja": "自動スナップショットの保持日数が最小要件日数（7 日）未満です",
		"de": "Automatische Snapshot-Aufbewahrungstage sind weniger als die mindestens erforderlichen Tage (7 Tage)",
		"es": "Los días de retención de snapshot automático son menores que los días mínimos requeridos (7 días)",
		"fr": "Les jours de rétention de snapshot automatique sont inférieurs aux jours minimum requis (7 jours)",
		"pt": "Os dias de retenção de snapshot automático são menores que os dias mínimos necessários (7 dias)",
	},
	"recommendation": {
		"en": "Set auto snapshot retention days to at least 7 days to ensure adequate backup coverage",
		"zh": "将自动快照保留天数设置为至少 7 天以确保足够的备份覆盖",
		"ja": "十分なバックアップカバレッジを確保するために、自動スナップショットの保持日数を少なくとも 7 日に設定します",
		"de": "Setzen Sie die automatischen Snapshot-Aufbewahrungstage auf mindestens 7 Tage, um eine angemessene Backup-Abdeckung sicherzustellen",
		"es": "Establezca los días de retención de snapshot automático en al menos 7 días para asegurar una cobertura de respaldo adecuada",
		"fr": "Définissez les jours de rétention de snapshot automatique sur au moins 7 jours pour assurer une couverture de sauvegarde adéquate",
		"pt": "Defina os dias de retenção de snapshot automático para pelo menos 7 dias para garantir cobertura de backup adequada",
	},
}

# Minimum retention days requirement
min_retention_days := 7

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::AutoSnapshotPolicy")

	# Get retention days (-1 means permanent, which is compliant)
	retention_days := helpers.get_property(resource, "RetentionDays", 0)

	# Check if retention is less than minimum (but not -1 for permanent)
	retention_days != -1
	retention_days < min_retention_days

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RetentionDays"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
