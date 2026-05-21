package infraguard.rules.terraform.oss_bucket_backup_enable

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-backup-enable",
	"severity": "medium",
	"name": {
		"en": "OSS Backup Enabled",
		"zh": "OSS 开启备份",
		"ja": "OSS バックアップが有効",
		"de": "OSS-Backup aktiviert",
		"es": "Respaldo OSS Habilitado",
		"fr": "Sauvegarde OSS Activée",
		"pt": "Backup OSS Habilitado"
	},
	"description": {
		"en": "Ensures OSS bucket has versioning enabled for backup purposes.",
		"zh": "确保 OSS 存储桶开启版本控制以实现备份。",
		"ja": "OSS バケットでバックアップまたはバージョン管理が有効になっていることを確認します。",
		"de": "Stellt sicher, dass OSS-Buckets Backup oder Versionskontrolle aktiviert haben.",
		"es": "Garantiza que los buckets OSS tengan respaldo o control de versiones habilitado.",
		"fr": "Garantit que les buckets OSS ont la sauvegarde ou le contrôle de version activé.",
		"pt": "Garante que os buckets OSS tenham backup ou controle de versão habilitado."
	},
	"reason": {
		"en": "The OSS bucket does not have versioning enabled for backup.",
		"zh": "OSS 存储桶未开启版本控制进行备份。",
		"ja": "バックアップとバージョン管理により、誤削除や変更によるデータ損失を防ぎます。",
		"de": "Backups und Versionskontrolle verhindern Datenverlust durch versehentliches Löschen oder Ändern.",
		"es": "Las copias de seguridad y el control de versiones previenen la pérdida de datos por eliminación o modificación accidental.",
		"fr": "Les sauvegardes et le contrôle de version empêchent la perte de données due à une suppression ou modification accidentelle.",
		"pt": "Backups e controle de versão previnem perda de dados por exclusão ou modificação acidental."
	},
	"recommendation": {
		"en": "Enable versioning on the OSS bucket by setting versioning status to 'Enabled'.",
		"zh": "通过将版本控制状态设置为 'Enabled' 来开启 OSS 存储桶的版本控制。",
		"ja": "OSS バケットのバージョン管理またはクロスリージョンレプリケーションを有効にします。",
		"de": "Aktivieren Sie Versionskontrolle oder regionsübergreifende Replikation für den OSS-Bucket.",
		"es": "Habilite el control de versiones o la replicación entre regiones para el bucket OSS.",
		"fr": "Activez le contrôle de version ou la réplication inter-régions pour le bucket OSS.",
		"pt": "Habilite o controle de versão ou a replicação entre regiões para o bucket OSS."
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
