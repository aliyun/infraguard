package infraguard.rules.aliyun.kafka_instance_disk_encrypted

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "kafka-instance-disk-encrypted",
	"severity": "high",
	"name": {
		"en": "Kafka Instance Disk Encrypted",
		"zh": "Kafka 实例部署时启用了云盘加密",
		"ja": "Kafka インスタンスディスク暗号化",
		"de": "Kafka-Instanz Festplatte verschlüsselt",
		"es": "Disco de Instancia Kafka Cifrado",
		"fr": "Disque d'Instance Kafka Chiffré",
		"pt": "Disco de Instância Kafka Criptografado"
	},
	"description": {
		"en": "Kafka instance should have disk encryption enabled during deployment for data protection.",
		"zh": "Kafka 实例部署时启用了云盘加密，视为合规。Serverless 或非服务中的实例视为不适用。",
		"ja": "Kafka インスタンスは、データ保護のためにデプロイ時にディスク暗号化を有効にする必要があります。",
		"de": "Kafka-Instanz sollte während der Bereitstellung Festplattenverschlüsselung für den Datenschutz aktiviert haben.",
		"es": "La instancia Kafka debe tener cifrado de disco habilitado durante la implementación para protección de datos.",
		"fr": "L'instance Kafka doit avoir le chiffrement de disque activé lors du déploiement pour la protection des données.",
		"pt": "A instância Kafka deve ter criptografia de disco habilitada durante a implantação para proteção de dados."
	},
	"reason": {
		"en": "Kafka instance does not have disk encryption enabled, which may expose data to security risks.",
		"zh": "Kafka 实例未启用云盘加密，可能导致数据面临安全风险。",
		"ja": "Kafka インスタンスでディスク暗号化が有効になっていないため、データがセキュリティリスクにさらされる可能性があります。",
		"de": "Kafka-Instanz hat keine Festplattenverschlüsselung aktiviert, was Daten Sicherheitsrisiken aussetzen kann.",
		"es": "La instancia Kafka no tiene cifrado de disco habilitado, lo que puede exponer los datos a riesgos de seguridad.",
		"fr": "L'instance Kafka n'a pas le chiffrement de disque activé, ce qui peut exposer les données à des risques de sécurité.",
		"pt": "A instância Kafka não tem criptografia de disco habilitada, o que pode expor os dados a riscos de segurança."
	},
	"recommendation": {
		"en": "Enable disk encryption by configuring KMSKeyId in DeployOption when deploying the Kafka instance.",
		"zh": "在部署 Kafka 实例时，通过在 DeployOption 中配置 KMSKeyId 来启用云盘加密。",
		"ja": "Kafka インスタンスをデプロイする際に、DeployOption で KMSKeyId を設定してディスク暗号化を有効にします。",
		"de": "Aktivieren Sie die Festplattenverschlüsselung, indem Sie KMSKeyId in DeployOption konfigurieren, wenn Sie die Kafka-Instanz bereitstellen.",
		"es": "Habilite el cifrado de disco configurando KMSKeyId en DeployOption al implementar la instancia Kafka.",
		"fr": "Activez le chiffrement de disque en configurant KMSKeyId dans DeployOption lors du déploiement de l'instance Kafka.",
		"pt": "Habilite a criptografia de disco configurando KMSKeyId em DeployOption ao implantar a instância Kafka."
	},
	"resource_types": ["ALIYUN::KAFKA::Instance"]
}

# Check if the instance is serverless (not applicable)
is_serverless(resource) if {
	resource.Properties.PayType == "Serverless"
}

# Check if disk encryption is enabled via KMSKeyId in DeployOption
is_disk_encrypted(resource) if {
	resource.Properties.DeployOption.KMSKeyId != null
}

# Generate deny for non-compliant resources
# Skip serverless instances as they are not applicable
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KAFKA::Instance")
	not is_serverless(resource)
	not is_disk_encrypted(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeployOption", "KMSKeyId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
