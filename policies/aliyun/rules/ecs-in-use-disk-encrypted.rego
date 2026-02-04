package infraguard.rules.aliyun.ecs_in_use_disk_encrypted

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-in-use-disk-encrypted",
	"name": {
		"en": "ECS In-Use Disk Encryption",
		"zh": "使用中的 ECS 数据磁盘开启加密",
		"ja": "ECS 使用中ディスクの暗号化",
		"de": "ECS-Disk-Verschlüsselung in Verwendung",
		"es": "Cifrado de Disco en Uso de ECS",
		"fr": "Chiffrement de Disque en Utilisation ECS",
		"pt": "Criptografia de Disco em Uso ECS",
	},
	"severity": "medium",
	"description": {
		"en": "ECS data disks should have encryption enabled to protect data at rest. Encrypted disks use KMS keys to encrypt data, ensuring data security and compliance with regulatory requirements.",
		"zh": "使用中的 ECS 数据磁盘应开启加密以保护静态数据。加密磁盘使用 KMS 密钥对数据进行加密，确保数据安全并符合合规要求。",
		"ja": "ECS データディスクは、保存データを保護するために暗号化を有効にする必要があります。暗号化されたディスクは KMS キーを使用してデータを暗号化し、データのセキュリティと規制要件への準拠を確保します。",
		"de": "ECS-Datendisks sollten Verschlüsselung aktiviert haben, um ruhende Daten zu schützen. Verschlüsselte Disks verwenden KMS-Schlüssel zur Datenverschlüsselung und gewährleisten Datensicherheit und Compliance mit regulatorischen Anforderungen.",
		"es": "Los discos de datos ECS deben tener cifrado habilitado para proteger los datos en reposo. Los discos cifrados usan claves KMS para cifrar datos, asegurando la seguridad de los datos y el cumplimiento de los requisitos regulatorios.",
		"fr": "Les disques de données ECS doivent avoir le chiffrement activé pour protéger les données au repos. Les disques chiffrés utilisent des clés KMS pour chiffrer les données, garantissant la sécurité des données et la conformité aux exigences réglementaires.",
		"pt": "Discos de dados ECS devem ter criptografia habilitada para proteger dados em repouso. Discos criptografados usam chaves KMS para criptografar dados, garantindo segurança de dados e conformidade com requisitos regulatórios.",
	},
	"reason": {
		"en": "The ECS disk does not have encryption enabled, which may expose sensitive data to unauthorized access.",
		"zh": "ECS 磁盘未开启加密，可能导致敏感数据暴露给未授权访问。",
		"ja": "ECS ディスクで暗号化が有効になっていないため、機密データが不正アクセスにさらされる可能性があります。",
		"de": "Die ECS-Disk hat keine Verschlüsselung aktiviert, was sensible Daten unbefugtem Zugriff aussetzen kann.",
		"es": "El disco ECS no tiene cifrado habilitado, lo que puede exponer datos sensibles a acceso no autorizado.",
		"fr": "Le disque ECS n'a pas le chiffrement activé, ce qui peut exposer des données sensibles à un accès non autorisé.",
		"pt": "O disco ECS não tem criptografia habilitada, o que pode expor dados sensíveis a acesso não autorizado.",
	},
	"recommendation": {
		"en": "Enable encryption for the ECS disk by setting the Encrypted property to true.",
		"zh": "通过将 Encrypted 属性设置为 true 来为 ECS 磁盘启用加密。",
		"ja": "Encrypted プロパティを true に設定して、ECS ディスクの暗号化を有効にします。",
		"de": "Aktivieren Sie die Verschlüsselung für die ECS-Disk, indem Sie die Encrypted-Eigenschaft auf true setzen.",
		"es": "Habilite el cifrado para el disco ECS estableciendo la propiedad Encrypted en true.",
		"fr": "Activez le chiffrement pour le disque ECS en définissant la propriété Encrypted sur true.",
		"pt": "Habilite criptografia para o disco ECS definindo a propriedade Encrypted como true.",
	},
	"resource_types": ["ALIYUN::ECS::Disk"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")
	not is_encrypted(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Encrypted"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

is_encrypted(resource) if {
	resource.Properties.Encrypted == true
}
