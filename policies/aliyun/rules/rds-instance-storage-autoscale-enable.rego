package infraguard.rules.aliyun.rds_instance_storage_autoscale_enable

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rds-instance-storage-autoscale-enable",
	"name": {
		"en": "RDS Storage Autoscale Enabled",
		"zh": "RDS 开启存储自动扩容",
		"ja": "RDS ストレージ自動スケールが有効",
		"de": "RDS-Speicher-Autoscale aktiviert",
		"es": "Autoescalado de Almacenamiento RDS Habilitado",
		"fr": "Mise à l'Échelle Automatique du Stockage RDS Activée",
		"pt": "Autoescala de Armazenamento RDS Habilitada"
	},
	"severity": "low",
	"description": {
		"en": "Ensures RDS instances have storage autoscale enabled to prevent downtime due to full disks.",
		"zh": "确保 RDS 实例开启了存储自动扩容，以防止因磁盘满载导致的服务中断。",
		"ja": "RDS インスタンスでストレージ自動スケールが有効になっていることを確認し、ディスク満杯によるダウンタイムを防ぎます。",
		"de": "Stellt sicher, dass RDS-Instanzen Speicher-Autoscale aktiviert haben, um Ausfallzeiten aufgrund voller Festplatten zu verhindern.",
		"es": "Garantiza que las instancias RDS tengan autoescalado de almacenamiento habilitado para prevenir tiempo de inactividad debido a discos llenos.",
		"fr": "Garantit que les instances RDS ont la mise à l'échelle automatique du stockage activée pour éviter les temps d'arrêt dus aux disques pleins.",
		"pt": "Garante que as instâncias RDS tenham autoescala de armazenamento habilitada para prevenir tempo de inatividade devido a discos cheios."
	},
	"reason": {
		"en": "Automatic scaling ensures that the database doesn't run out of storage space.",
		"zh": "自动扩容确保数据库不会因存储空间耗尽而受限。",
		"ja": "自動スケーリングにより、データベースがストレージスペースを使い果たすことがなくなります。",
		"de": "Automatische Skalierung stellt sicher, dass der Datenbank der Speicherplatz nicht ausgeht.",
		"es": "El escalado automático garantiza que la base de datos no se quede sin espacio de almacenamiento.",
		"fr": "La mise à l'échelle automatique garantit que la base de données ne manque pas d'espace de stockage.",
		"pt": "O escalonamento automático garante que o banco de dados não fique sem espaço de armazenamento."
	},
	"recommendation": {
		"en": "Set StorageAutoScale to 'Enable' for the RDS instance.",
		"zh": "为 RDS 实例将 StorageAutoScale 设置为 'Enable'。",
		"ja": "RDS インスタンスの StorageAutoScale を 'Enable' に設定します。",
		"de": "Setzen Sie StorageAutoScale für die RDS-Instanz auf 'Enable'.",
		"es": "Establezca StorageAutoScale en 'Enable' para la instancia RDS.",
		"fr": "Définissez StorageAutoScale sur 'Enable' pour l'instance RDS.",
		"pt": "Defina StorageAutoScale como 'Enable' para a instância RDS."
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

is_compliant(resource) if {
	helpers.get_property(resource, "StorageAutoScale", "Disable") == "Enable"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "StorageAutoScale"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
