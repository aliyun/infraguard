package infraguard.rules.aliyun.ack_cluster_encryption_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ack-cluster-encryption-enabled",
	"severity": "medium",
	"name": {
		"en": "ACK Cluster Secret Encryption Enabled",
		"zh": "ACK 集群配置 Secret 的落盘加密",
		"ja": "ACK クラスタの Secret 暗号化が有効",
		"de": "ACK-Cluster Secret-Verschlüsselung aktiviert",
		"es": "Cifrado de Secret del Cluster ACK Habilitado",
		"fr": "Chiffrement Secret du Cluster ACK Activé",
		"pt": "Criptografia de Secret do Cluster ACK Habilitada"
	},
	"description": {
		"en": "ACK Pro clusters should have Secret encryption at rest enabled using KMS.",
		"zh": "ACK 集群配置 Secret 的落盘加密，视为合规。非专业托管版集群视为不适用。",
		"ja": "ACK Pro クラスタは KMS を使用して Secret の保存時暗号化を有効にする必要があります。",
		"de": "ACK Pro-Cluster sollten Secret-Verschlüsselung im Ruhezustand mit KMS aktiviert haben.",
		"es": "Los clústeres ACK Pro deben tener cifrado de Secret en reposo habilitado usando KMS.",
		"fr": "Les clusters ACK Pro doivent avoir le chiffrement Secret au repos activé avec KMS.",
		"pt": "Clusters ACK Pro devem ter criptografia de Secret em repouso habilitada usando KMS."
	},
	"reason": {
		"en": "The ACK Pro cluster does not have Secret encryption at rest enabled.",
		"zh": "ACK 专业版集群未开启 Secret 落盘加密。",
		"ja": "ACK Pro クラスタで Secret の保存時暗号化が有効になっていません。",
		"de": "Der ACK Pro-Cluster hat keine Secret-Verschlüsselung im Ruhezustand aktiviert.",
		"es": "El clúster ACK Pro no tiene cifrado de Secret en reposo habilitado.",
		"fr": "Le cluster ACK Pro n'a pas le chiffrement Secret au repos activé.",
		"pt": "O cluster ACK Pro não tem criptografia de Secret em repouso habilitada."
	},
	"recommendation": {
		"en": "Enable Secret encryption by specifying EncryptionProviderKey.",
		"zh": "通过指定 EncryptionProviderKey 开启 Secret 加密。",
		"ja": "EncryptionProviderKey を指定して Secret 暗号化を有効にします。",
		"de": "Aktivieren Sie die Secret-Verschlüsselung, indem Sie EncryptionProviderKey angeben.",
		"es": "Habilite el cifrado de Secret especificando EncryptionProviderKey.",
		"fr": "Activez le chiffrement Secret en spécifiant EncryptionProviderKey.",
		"pt": "Habilite a criptografia de Secret especificando EncryptionProviderKey."
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster"]
}

# Check if cluster is ACK Pro
is_ack_pro(resource) if {
	helpers.get_property(resource, "ClusterSpec", "") == "ack.pro.small"
}

# Check if encryption is enabled
is_encryption_enabled(resource) if {
	helpers.has_property(resource, "EncryptionProviderKey")
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	is_ack_pro(resource)
	not is_encryption_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EncryptionProviderKey"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
