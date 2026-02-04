package infraguard.rules.aliyun.oss_bucket_backup_enable

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "oss-bucket-backup-enable",
	"name": {
		"en": "OSS Backup Enabled",
		"zh": "OSS 开启备份",
		"ja": "OSS バックアップが有効",
		"de": "OSS-Backup aktiviert",
		"es": "Respaldo OSS Habilitado",
		"fr": "Sauvegarde OSS Activée",
		"pt": "Backup OSS Habilitado",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures OSS buckets have backup or versioning enabled.",
		"zh": "确保 OSS 存储桶开启了备份或版本控制。",
		"ja": "OSS バケットでバックアップまたはバージョン管理が有効になっていることを確認します。",
		"de": "Stellt sicher, dass OSS-Buckets Backup oder Versionskontrolle aktiviert haben.",
		"es": "Garantiza que los buckets OSS tengan respaldo o control de versiones habilitado.",
		"fr": "Garantit que les buckets OSS ont la sauvegarde ou le contrôle de version activé.",
		"pt": "Garante que os buckets OSS tenham backup ou controle de versão habilitado.",
	},
	"reason": {
		"en": "Backups and versioning prevent data loss from accidental deletion or modification.",
		"zh": "备份和版本控制可防止因意外删除或修改导致的数据丢失。",
		"ja": "バックアップとバージョン管理により、誤削除や変更によるデータ損失を防ぎます。",
		"de": "Backups und Versionskontrolle verhindern Datenverlust durch versehentliches Löschen oder Ändern.",
		"es": "Las copias de seguridad y el control de versiones previenen la pérdida de datos por eliminación o modificación accidental.",
		"fr": "Les sauvegardes et le contrôle de version empêchent la perte de données due à une suppression ou modification accidentelle.",
		"pt": "Backups e controle de versão previnem perda de dados por exclusão ou modificação acidental.",
	},
	"recommendation": {
		"en": "Enable versioning or cross-region replication for the OSS bucket.",
		"zh": "为 OSS 存储桶开启版本控制或跨区域复制。",
		"ja": "OSS バケットのバージョン管理またはクロスリージョンレプリケーションを有効にします。",
		"de": "Aktivieren Sie Versionskontrolle oder regionsübergreifende Replikation für den OSS-Bucket.",
		"es": "Habilite el control de versiones o la replicación entre regiones para el bucket OSS.",
		"fr": "Activez le contrôle de version ou la réplication inter-régions pour le bucket OSS.",
		"pt": "Habilite o controle de versão ou a replicação entre regiões para o bucket OSS.",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

is_compliant(resource) if {
	# Versioning check
	v := helpers.get_property(resource, "VersioningConfiguration", {})
	v.Status == "Enabled"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VersioningConfiguration"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
