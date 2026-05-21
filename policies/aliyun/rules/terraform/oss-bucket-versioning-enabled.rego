package infraguard.rules.terraform.oss_bucket_versioning_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-versioning-enabled",
	"severity": "medium",
	"name": {
		"en": "OSS Bucket Versioning Enabled",
		"zh": "OSS 存储桶开启版本控制",
		"ja": "OSS バケットのバージョニングが有効",
		"de": "OSS-Bucket Versionsverwaltung aktiviert",
		"es": "Versionado de Bucket OSS Habilitado",
		"fr": "Versioning de Bucket OSS Activé",
		"pt": "Versionamento de Bucket OSS Habilitado"
	},
	"description": {
		"en": "Ensures OSS bucket has versioning enabled.",
		"zh": "确保 OSS 存储桶开启了版本控制。",
		"ja": "OSS バケットは、誤削除や上書きから保護するためにバージョニングを有効にする必要があります。",
		"de": "OSS-Bucket sollte Versionsverwaltung aktiviert haben, um vor versehentlichem Löschen oder Überschreiben zu schützen.",
		"es": "El bucket OSS debe tener versionado habilitado para proteger contra eliminación o sobrescritura accidental.",
		"fr": "Le bucket OSS doit avoir le versioning activé pour protéger contre la suppression ou l'écrasement accidentel.",
		"pt": "Bucket OSS deve ter versionamento habilitado para proteger contra exclusão ou sobrescrita acidental."
	},
	"reason": {
		"en": "The OSS bucket does not have versioning enabled.",
		"zh": "OSS 存储桶未开启版本控制。",
		"ja": "OSS バケットでバージョニングが有効になっていないため、データ損失のリスクが増加します。",
		"de": "Die Versionsverwaltung ist für den OSS-Bucket nicht aktiviert, was das Risiko von Datenverlust erhöht.",
		"es": "El versionado no está habilitado para el bucket OSS, lo que aumenta el riesgo de pérdida de datos.",
		"fr": "Le versioning n'est pas activé pour le bucket OSS, ce qui augmente le risque de perte de données.",
		"pt": "Versionamento não está habilitado para o bucket OSS, o que aumenta o risco de perda de dados."
	},
	"recommendation": {
		"en": "Enable versioning on the OSS bucket by setting versioning status to 'Enabled'.",
		"zh": "通过将版本控制状态设置为 'Enabled' 来开启 OSS 存储桶的版本控制。",
		"ja": "VersioningConfiguration.Status を Enabled に設定して、OSS バケットのバージョニングを有効にします。",
		"de": "Aktivieren Sie die Versionsverwaltung für den OSS-Bucket, indem Sie VersioningConfiguration.Status auf Enabled setzen.",
		"es": "Habilite el versionado para el bucket OSS estableciendo VersioningConfiguration.Status en Enabled.",
		"fr": "Activez le versioning pour le bucket OSS en définissant VersioningConfiguration.Status sur Enabled.",
		"pt": "Habilite versionamento para o bucket OSS definindo VersioningConfiguration.Status como Enabled."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

is_versioning_enabled(resource) if {
	versioning := tf.get_attribute(resource, "versioning", {})
	status := object.get(versioning, "status", "")
	status == "Enabled"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	not is_versioning_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_oss_bucket.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
