package infraguard.rules.terraform.oss_bucket_anonymous_prohibited

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-anonymous-prohibited",
	"severity": "high",
	"name": {
		"en": "OSS Bucket Anonymous Access Prohibited",
		"zh": "OSS 存储桶禁用匿名访问",
		"ja": "OSS バケットの匿名アクセスが禁止",
		"de": "OSS-Bucket anonyme Zugriffe verboten",
		"es": "Acceso Anónimo de Bucket OSS Prohibido",
		"fr": "Accès Anonyme au Bucket OSS Interdit",
		"pt": "Acesso Anônimo de Bucket OSS Proibido"
	},
	"description": {
		"en": "Ensures OSS bucket ACL is set to private to prevent anonymous access.",
		"zh": "确保 OSS 存储桶 ACL 设置为私有，防止匿名访问。",
		"ja": "OSS バケットで匿名アクセスが禁止されていることを確認します。",
		"de": "Stellt sicher, dass anonyme Zugriffe für den OSS-Bucket verboten sind.",
		"es": "Garantiza que el acceso anónimo esté prohibido para el bucket OSS.",
		"fr": "Garantit que l'accès anonyme est interdit pour le bucket OSS.",
		"pt": "Garante que o acesso anônimo esteja proibido para o bucket OSS."
	},
	"reason": {
		"en": "The OSS bucket ACL is not set to private, which allows anonymous access.",
		"zh": "OSS 存储桶 ACL 未设置为私有，允许匿名访问。",
		"ja": "OSS バケットへの匿名アクセスは、不正なデータ公開のリスクを増加させます。",
		"de": "Anonymer Zugriff auf einen OSS-Bucket erhöht das Risiko einer unbefugten Datenexposition.",
		"es": "El acceso anónimo a un bucket OSS aumenta el riesgo de exposición no autorizada de datos.",
		"fr": "L'accès anonyme à un bucket OSS augmente le risque d'exposition non autorisée des données.",
		"pt": "O acesso anônimo a um bucket OSS aumenta o risco de exposição não autorizada de dados."
	},
	"recommendation": {
		"en": "Set the bucket ACL to 'private' to prevent anonymous access.",
		"zh": "将存储桶 ACL 设置为 'private' 以防止匿名访问。",
		"ja": "OSS バケット ACL を 'private' に設定し、匿名ユーザーにパブリック読み取り/書き込み権限が付与されていないことを確認します。",
		"de": "Konfigurieren Sie die OSS-Bucket-ACL auf 'private' und stellen Sie sicher, dass anonymen Benutzern keine öffentlichen Lese-/Schreibberechtigungen gewährt werden.",
		"es": "Configure el ACL del bucket OSS en 'private' y asegúrese de que no se otorguen permisos de lectura/escritura públicos a usuarios anónimos.",
		"fr": "Configurez l'ACL du bucket OSS sur 'private' et assurez-vous qu'aucune permission de lecture/écriture publique n'est accordée aux utilisateurs anonymes.",
		"pt": "Configure o ACL do bucket OSS como 'private' e garanta que nenhuma permissão de leitura/gravação pública seja concedida a usuários anônimos."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	acl := tf.get_attribute(resource, "acl", "private")
	not tf.is_unknown(acl)
	acl != "private"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_oss_bucket.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
