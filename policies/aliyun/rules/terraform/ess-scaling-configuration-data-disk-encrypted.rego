package infraguard.rules.terraform.ess_scaling_configuration_data_disk_encrypted

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ess-scaling-configuration-data-disk-encrypted",
	"severity": "high",
	"name": {
		"en": "ESS Scaling Configuration Data Disk Encryption",
		"zh": "弹性伸缩配置中设置数据磁盘加密",
		"ja": "ESS スケーリング設定データディスク暗号化",
		"de": "ESS-Skalierungskonfiguration Datenfestplattenverschlüsselung",
		"es": "Cifrado de Disco de Datos de Configuración de Escalado ESS",
		"fr": "Chiffrement de Disque de Données de Configuration de Mise à l'Échelle ESS",
		"pt": "Criptografia de Disco de Dados de Configuração de Escalonamento ESS"
	},
	"description": {
		"en": "All ESS scaling configuration data disks should be encrypted.",
		"zh": "弹性伸缩配置中数据磁盘配置均设置为加密，视为合规。",
		"ja": "ESS スケーリング設定は、保存データを保護するためにデータディスク暗号化を有効にする必要があります。",
		"de": "ESS-Skalierungskonfigurationen sollten Datenfestplattenverschlüsselung aktivieren, um ruhende Daten zu schützen.",
		"es": "Las configuraciones de escalado ESS deben habilitar el cifrado de disco de datos para proteger los datos en reposo.",
		"fr": "Les configurations de mise à l'échelle ESS doivent activer le chiffrement des disques de données pour protéger les données au repos.",
		"pt": "As configurações de escalonamento ESS devem habilitar a criptografia de disco de dados para proteger dados em repouso."
	},
	"reason": {
		"en": "The ESS scaling configuration has data disks that are not encrypted.",
		"zh": "弹性伸缩配置中的数据磁盘未加密，静态数据可能面临泄露风险。",
		"ja": "ESS スケーリング設定に暗号化されていないデータディスクがあり、保存データが漏洩する可能性があります。",
		"de": "Die ESS-Skalierungskonfiguration hat Datenfestplatten, die nicht verschlüsselt sind, was ruhende sensible Daten aussetzen kann.",
		"es": "La configuración de escalado ESS tiene discos de datos que no están cifrados, lo que puede exponer datos sensibles en reposo.",
		"fr": "La configuration de mise à l'échelle ESS a des disques de données qui ne sont pas chiffrés, ce qui peut exposer des données sensibles au repos.",
		"pt": "A configuração de escalonamento ESS tem discos de dados que não estão criptografados, o que pode expor dados sensíveis em repouso."
	},
	"recommendation": {
		"en": "Set encrypted = true on each data_disk block.",
		"zh": "为所有数据磁盘启用加密。",
		"ja": "スケーリング設定で DiskMappings[*].Encrypted を true に設定して、すべてのデータディスクの暗号化を有効にします。",
		"de": "Aktivieren Sie die Verschlüsselung für alle Datenfestplatten in der Skalierungskonfiguration, indem Sie DiskMappings[*].Encrypted auf true setzen.",
		"es": "Habilite el cifrado para todos los discos de datos en la configuración de escalado estableciendo DiskMappings[*].Encrypted en true.",
		"fr": "Activez le chiffrement pour tous les disques de données dans la configuration de mise à l'échelle en définissant DiskMappings[*].Encrypted sur true.",
		"pt": "Habilite a criptografia para todos os discos de dados na configuração de escalonamento definindo DiskMappings[*].Encrypted como true."
	},
	"resource_types": ["alicloud_ess_scaling_configuration"],
	"iac_type": "terraform"
}

disk_encrypted(disk) if {
	tf.get_attribute(disk, "encrypted", false) == true
}

disk_encrypted(disk) if {
	tf.get_attribute(disk, "encrypted", "") == "true"
}

has_unencrypted_data_disk(data_disks) if {
	is_array(data_disks)
	some disk in data_disks
	not disk_encrypted(disk)
}

has_unencrypted_data_disk(data_disks) if {
	is_object(data_disks)
	not disk_encrypted(data_disks)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ess_scaling_configuration")
	data_disks := tf.get_attribute(resource, "data_disk", [])
	not tf.is_unknown(data_disks)
	has_unencrypted_data_disk(data_disks)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ess_scaling_configuration.%s", [name]),
		"violation_path": ["data_disk", "encrypted"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
