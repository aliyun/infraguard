package infraguard.rules.aliyun.ess_scaling_configuration_system_disk_encrypted

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-scaling-configuration-system-disk-encrypted",
	"name": {
		"en": "ESS Scaling Configuration System Disk Encryption",
		"zh": "弹性伸缩配置中设置系统磁盘加密",
		"ja": "ESS スケーリング設定のシステムディスク暗号化",
		"de": "ESS-Skalierungskonfiguration System-Disk-Verschlüsselung",
		"es": "Cifrado de Disco del Sistema de Configuración de Escalado ESS",
		"fr": "Chiffrement du Disque Système de la Configuration de Mise à l'Échelle ESS",
		"pt": "Criptografia de Disco do Sistema da Configuração de Escalonamento ESS"
	},
	"severity": "high",
	"description": {
		"en": "ESS scaling configurations should enable system disk encryption to protect system data at rest.",
		"zh": "弹性伸缩配置中系统磁盘配置设置为加密，视为合规。",
		"ja": "ESS スケーリング設定は、保存データを保護するためにシステムディスク暗号化を有効にする必要があります。",
		"de": "ESS-Skalierungskonfigurationen sollten System-Disk-Verschlüsselung aktivieren, um Systemdaten im Ruhezustand zu schützen.",
		"es": "Las configuraciones de escalado ESS deben habilitar el cifrado del disco del sistema para proteger los datos del sistema en reposo.",
		"fr": "Les configurations de mise à l'échelle ESS doivent activer le chiffrement du disque système pour protéger les données système au repos.",
		"pt": "As configurações de escalonamento ESS devem habilitar a criptografia do disco do sistema para proteger os dados do sistema em repouso."
	},
	"reason": {
		"en": "The ESS scaling configuration does not have system disk encryption enabled.",
		"zh": "弹性伸缩配置中的系统磁盘未加密，静态数据可能面临泄露风险。",
		"ja": "ESS スケーリング設定でシステムディスク暗号化が有効になっていません。",
		"de": "Die ESS-Skalierungskonfiguration hat keine System-Disk-Verschlüsselung aktiviert.",
		"es": "La configuración de escalado ESS no tiene cifrado del disco del sistema habilitado.",
		"fr": "La configuration de mise à l'échelle ESS n'a pas le chiffrement du disque système activé.",
		"pt": "A configuração de escalonamento ESS não tem criptografia do disco do sistema habilitada."
	},
	"recommendation": {
		"en": "Enable system disk encryption in the scaling configuration settings.",
		"zh": "在伸缩配置中启用系统磁盘加密功能。",
		"ja": "スケーリング設定でシステムディスク暗号化を有効にします。",
		"de": "Aktivieren Sie die System-Disk-Verschlüsselung in den Skalierungskonfigurationseinstellungen.",
		"es": "Habilite el cifrado del disco del sistema en la configuración de escalado.",
		"fr": "Activez le chiffrement du disque système dans les paramètres de configuration de mise à l'échelle.",
		"pt": "Habilite a criptografia do disco do sistema nas configurações de escalonamento."
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"],
}

# Check if system disk encryption is enabled
is_system_disk_encrypted(resource) if {
	system_disk_encrypted := helpers.get_property(resource, "SystemDiskEncryptAlgorithm", "")
	system_disk_encrypted != ""
}

is_system_disk_encrypted(resource) if {
	kms_key_id := helpers.get_property(resource, "SystemDiskKMSKeyId", "")
	kms_key_id != ""
}

# If no explicit encryption setting, consider it non-compliant
# Note: Some images have default encryption, but explicit configuration is preferred
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not is_system_disk_encrypted(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SystemDiskEncryptAlgorithm"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
