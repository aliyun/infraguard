package infraguard.rules.aliyun.mongodb_instance_release_protection

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-instance-release-protection",
	"severity": "medium",
	"name": {
		"en": "MongoDB Instance Release Protection Enabled",
		"zh": "MongoDB 实例开启释放保护",
		"ja": "MongoDB インスタンス解放保護が有効",
		"de": "MongoDB-Instanz Freigabeschutz aktiviert",
		"es": "Protección de Liberación de Instancia MongoDB Habilitada",
		"fr": "Protection contre la Libération d'Instance MongoDB Activée",
		"pt": "Proteção contra Liberação de Instância MongoDB Habilitada"
	},
	"description": {
		"en": "Ensures that MongoDB instances have release protection enabled.",
		"zh": "确保 MongoDB 实例开启了释放保护。",
		"ja": "MongoDB インスタンスで解放保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen Freigabeschutz aktiviert haben.",
		"es": "Garantiza que las instancias MongoDB tengan protección contra liberación habilitada.",
		"fr": "Garantit que les instances MongoDB ont la protection contre la libération activée.",
		"pt": "Garante que as instâncias MongoDB tenham proteção contra liberação habilitada."
	},
	"reason": {
		"en": "If release protection is not enabled, the MongoDB instance may be released accidentally, causing data loss.",
		"zh": "如果未开启释放保护，MongoDB 实例可能会被意外释放，导致数据丢失。",
		"ja": "解放保護が有効になっていない場合、MongoDB インスタンスが誤って解放され、データ損失が発生する可能性があります。",
		"de": "Wenn der Freigabeschutz nicht aktiviert ist, kann die MongoDB-Instanz versehentlich freigegeben werden, was zu Datenverlust führt.",
		"es": "Si la protección contra liberación no está habilitada, la instancia MongoDB puede ser liberada accidentalmente, causando pérdida de datos.",
		"fr": "Si la protection contre la libération n'est pas activée, l'instance MongoDB peut être libérée accidentellement, entraînant une perte de données.",
		"pt": "Se a proteção contra liberação não estiver habilitada, a instância MongoDB pode ser liberada acidentalmente, causando perda de dados."
	},
	"recommendation": {
		"en": "Enable release protection for the MongoDB instance.",
		"zh": "为 MongoDB 实例开启释放保护功能。",
		"ja": "MongoDB インスタンスの解放保護を有効にします。",
		"de": "Aktivieren Sie den Freigabeschutz für die MongoDB-Instanz.",
		"es": "Habilite la protección contra liberación para la instancia MongoDB.",
		"fr": "Activez la protection contre la libération pour l'instance MongoDB.",
		"pt": "Habilite a proteção contra liberação para a instância MongoDB."
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"]
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "DBInstanceReleaseProtection", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DBInstanceReleaseProtection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
