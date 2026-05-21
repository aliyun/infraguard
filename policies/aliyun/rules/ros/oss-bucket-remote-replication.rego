package infraguard.rules.aliyun.oss_bucket_remote_replication

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "oss-bucket-remote-replication",
	"severity": "medium",
	"name": {
		"en": "OSS Bucket Remote Replication Enabled",
		"zh": "OSS 存储桶开启跨区域复制",
		"ja": "OSS バケットリモートレプリケーションが有効",
		"de": "OSS-Bucket Remote-Replikation aktiviert",
		"es": "Replicación Remota de Bucket OSS Habilitada",
		"fr": "Réplication Distante de Bucket OSS Activée",
		"pt": "Replicação Remota de Bucket OSS Habilitada"
	},
	"description": {
		"en": "Ensures that cross-region replication is enabled for the OSS bucket for disaster recovery.",
		"zh": "确保 OSS 存储桶开启了跨区域复制，以进行容灾。",
		"ja": "災害復旧のために OSS バケットでクロスリージョンレプリケーションが有効になっていることを確認します。",
		"de": "Stellt sicher, dass die regionsübergreifende Replikation für den OSS-Bucket für die Notfallwiederherstellung aktiviert ist.",
		"es": "Garantiza que la replicación entre regiones esté habilitada para el bucket OSS para recuperación ante desastres.",
		"fr": "Garantit que la réplication inter-régions est activée pour le bucket OSS pour la reprise après sinistre.",
		"pt": "Garante que a replicação entre regiões esteja habilitada para o bucket OSS para recuperação de desastres."
	},
	"reason": {
		"en": "Cross-region replication ensures data durability and availability in case of a regional failure.",
		"zh": "跨区域复制可确保在发生区域性故障时数据的持久性和可用性。",
		"ja": "クロスリージョンレプリケーションにより、リージョン障害が発生した場合のデータの耐久性と可用性が確保されます。",
		"de": "Regionsübergreifende Replikation gewährleistet Datenbeständigkeit und Verfügbarkeit bei einem regionalen Ausfall.",
		"es": "La replicación entre regiones garantiza la durabilidad y disponibilidad de los datos en caso de una falla regional.",
		"fr": "La réplication inter-régions garantit la durabilité et la disponibilité des données en cas de défaillance régionale.",
		"pt": "A replicação entre regiões garante a durabilidade e disponibilidade dos dados em caso de falha regional."
	},
	"recommendation": {
		"en": "Enable cross-region replication for the OSS bucket.",
		"zh": "为 OSS 存储桶开启跨区域复制。",
		"ja": "OSS バケットのクロスリージョンレプリケーションを有効にします。",
		"de": "Aktivieren Sie die regionsübergreifende Replikation für den OSS-Bucket.",
		"es": "Habilite la replicación entre regiones para el bucket OSS.",
		"fr": "Activez la réplication inter-régions pour le bucket OSS.",
		"pt": "Habilite a replicação entre regiões para o bucket OSS."
	},
	"resource_types": ["ALIYUN::OSS::Bucket"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Conceptual check
	not helpers.has_property(resource, "ReplicationConfiguration")
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
