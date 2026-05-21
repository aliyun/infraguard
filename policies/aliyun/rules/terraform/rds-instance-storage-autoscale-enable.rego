package infraguard.rules.terraform.rds_instance_storage_autoscale_enable

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-instance-storage-autoscale-enable",
	"severity": "low",
	"name": {
		"en": "RDS Storage Autoscale Enabled",
		"zh": "RDS 开启存储自动扩容",
		"ja": "RDS ストレージ自動スケールが有効",
		"de": "RDS-Speicher-Autoscale aktiviert",
		"es": "Autoescalado de Almacenamiento RDS Habilitado",
		"fr": "Mise à l'Échelle Automatique du Stockage RDS Activée",
		"pt": "Autoescala de Armazenamento RDS Habilitada"
	},
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
		"en": "Set storage_auto_scale to \"Enable\" for the RDS instance.",
		"zh": "为 RDS 实例将 storage_auto_scale 设置为 \"Enable\"。",
		"ja": "RDS インスタンスの storage_auto_scale を \"Enable\" に設定します。",
		"de": "Setzen Sie storage_auto_scale für die RDS-Instanz auf \"Enable\".",
		"es": "Establezca storage_auto_scale en \"Enable\" para la instancia RDS.",
		"fr": "Définissez storage_auto_scale sur \"Enable\" pour l'instance RDS.",
		"pt": "Defina storage_auto_scale como \"Enable\" para a instância RDS."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	tf.get_attribute(resource, "storage_auto_scale", "") != "Enable"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
