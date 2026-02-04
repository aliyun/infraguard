package infraguard.rules.aliyun.rds_instacne_delete_protection_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rds-instacne-delete-protection-enabled",
	"name": {
		"en": "RDS Instance Deletion Protection Enabled",
		"zh": "RDS 实例开启删除保护",
		"ja": "RDS インスタンスの削除保護が有効",
		"de": "RDS-Instanz-Löschschutz aktiviert",
		"es": "Protección contra Eliminación de Instancia RDS Habilitada",
		"fr": "Protection contre la Suppression d'Instance RDS Activée",
		"pt": "Proteção contra Exclusão de Instância RDS Habilitada",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that RDS instances have deletion protection enabled.",
		"zh": "确保 RDS 实例开启了删除保护。",
		"ja": "RDS インスタンスで削除保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass RDS-Instanzen den Löschschutz aktiviert haben.",
		"es": "Garantiza que las instancias RDS tengan protección contra eliminación habilitada.",
		"fr": "Garantit que les instances RDS ont la protection contre la suppression activée.",
		"pt": "Garante que as instâncias RDS tenham proteção contra exclusão habilitada.",
	},
	"reason": {
		"en": "If deletion protection is not enabled, the RDS instance may be released accidentally, causing data loss.",
		"zh": "如果未开启删除保护，RDS 实例可能会被意外释放，导致数据丢失。",
		"ja": "削除保護が有効になっていない場合、RDS インスタンスが誤って解放され、データ損失が発生する可能性があります。",
		"de": "Wenn der Löschschutz nicht aktiviert ist, kann die RDS-Instanz versehentlich freigegeben werden, was zu Datenverlust führt.",
		"es": "Si la protección contra eliminación no está habilitada, la instancia RDS puede ser liberada accidentalmente, causando pérdida de datos.",
		"fr": "Si la protection contre la suppression n'est pas activée, l'instance RDS peut être libérée accidentellement, causant une perte de données.",
		"pt": "Se a proteção contra exclusão não estiver habilitada, a instância RDS pode ser liberada acidentalmente, causando perda de dados.",
	},
	"recommendation": {
		"en": "Enable deletion protection for the RDS instance.",
		"zh": "为 RDS 实例开启删除保护功能。",
		"ja": "RDS インスタンスで削除保護を有効にします。",
		"de": "Aktivieren Sie den Löschschutz für die RDS-Instanz.",
		"es": "Habilite protección contra eliminación para la instancia RDS.",
		"fr": "Activez la protection contre la suppression pour l'instance RDS.",
		"pt": "Habilite proteção contra exclusão para a instância RDS.",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DeletionProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeletionProtection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
