package infraguard.rules.terraform.kafka_instance_disk_encrypted

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "kafka-instance-disk-encrypted",
	"severity": "high",
	"name": {
		"en": "Kafka Instance Disk Encryption Enabled",
		"zh": "Kafka 实例磁盘加密已启用",
		"ja": "Kafka インスタンスのディスク暗号化が有効",
		"de": "Kafka-Instanz Festplattenverschlüsselung aktiviert",
		"es": "Cifrado de Disco de Instancia Kafka Habilitado",
		"fr": "Chiffrement de Disque de l'Instance Kafka Activé",
		"pt": "Criptografia de Disco da Instância Kafka Habilitada"
	},
	"description": {
		"en": "Kafka instances should have disk encryption enabled using KMS to protect data at rest.",
		"zh": "Kafka 实例应使用 KMS 启用磁盘加密以保护静态数据，视为合规。",
		"ja": "Kafka インスタンスは、保存データを保護するために KMS を使用してディスク暗号化を有効にする必要があります。",
		"de": "Kafka-Instanzen sollten die Festplattenverschlüsselung mit KMS aktiviert haben, um ruhende Daten zu schützen.",
		"es": "Las instancias de Kafka deben tener cifrado de disco habilitado usando KMS para proteger datos en reposo.",
		"fr": "Les instances Kafka doivent avoir le chiffrement de disque activé avec KMS pour protéger les données au repos.",
		"pt": "Instâncias Kafka devem ter criptografia de disco habilitada usando KMS para proteger dados em repouso."
	},
	"reason": {
		"en": "The Kafka instance does not have disk encryption enabled via KMS.",
		"zh": "Kafka 实例未通过 KMS 启用磁盘加密。",
		"ja": "Kafka インスタンスで KMS によるディスク暗号化が有効になっていません。",
		"de": "Die Kafka-Instanz hat keine Festplattenverschlüsselung über KMS aktiviert.",
		"es": "La instancia de Kafka no tiene cifrado de disco habilitado mediante KMS.",
		"fr": "L'instance Kafka n'a pas le chiffrement de disque activé via KMS.",
		"pt": "A instância Kafka não tem criptografia de disco habilitada via KMS."
	},
	"recommendation": {
		"en": "Enable disk encryption by specifying a KMS key ID in the kms_key_id attribute.",
		"zh": "通过在 kms_key_id 属性中指定 KMS 密钥 ID 来启用磁盘加密。",
		"ja": "kms_key_id 属性に KMS キー ID を指定してディスク暗号化を有効にします。",
		"de": "Aktivieren Sie die Festplattenverschlüsselung, indem Sie eine KMS-Schlüssel-ID im kms_key_id-Attribut angeben.",
		"es": "Habilite el cifrado de disco especificando un ID de clave KMS en el atributo kms_key_id.",
		"fr": "Activez le chiffrement de disque en spécifiant un ID de clé KMS dans l'attribut kms_key_id.",
		"pt": "Habilite a criptografia de disco especificando um ID de chave KMS no atributo kms_key_id."
	},
	"resource_types": ["alicloud_alikafka_instance"],
	"iac_type": "terraform"
}

is_encryption_enabled(resource) if {
	key := tf.get_attribute(resource, "kms_key_id", "")
	not tf.is_unknown(key)
	key != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_alikafka_instance")
	not is_encryption_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_alikafka_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
