package infraguard.rules.aliyun.oss_bucket_anonymous_prohibited

import rego.v1

import data.infraguard.helpers

# Rule metadata
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
		"en": "Ensures that anonymous access is prohibited for the OSS bucket.",
		"zh": "确保 OSS 存储桶禁用了匿名访问。",
		"ja": "OSS バケットで匿名アクセスが禁止されていることを確認します。",
		"de": "Stellt sicher, dass anonyme Zugriffe für den OSS-Bucket verboten sind.",
		"es": "Garantiza que el acceso anónimo esté prohibido para el bucket OSS.",
		"fr": "Garantit que l'accès anonyme est interdit pour le bucket OSS.",
		"pt": "Garante que o acesso anônimo esteja proibido para o bucket OSS."
	},
	"reason": {
		"en": "Anonymous access to an OSS bucket increases the risk of unauthorized data exposure.",
		"zh": "对 OSS 存储桶的匿名访问增加了数据未经授权泄露的风险。",
		"ja": "OSS バケットへの匿名アクセスは、不正なデータ公開のリスクを増加させます。",
		"de": "Anonymer Zugriff auf einen OSS-Bucket erhöht das Risiko einer unbefugten Datenexposition.",
		"es": "El acceso anónimo a un bucket OSS aumenta el riesgo de exposición no autorizada de datos.",
		"fr": "L'accès anonyme à un bucket OSS augmente le risque d'exposition non autorisée des données.",
		"pt": "O acesso anônimo a um bucket OSS aumenta o risco de exposição não autorizada de dados."
	},
	"recommendation": {
		"en": "Configure the OSS bucket ACL to 'private' and ensure no public read/write permissions are granted to anonymous users.",
		"zh": "将 OSS 存储桶 ACL 配置为'private'，并确保未向匿名用户授予公开读写权限。",
		"ja": "OSS バケット ACL を 'private' に設定し、匿名ユーザーにパブリック読み取り/書き込み権限が付与されていないことを確認します。",
		"de": "Konfigurieren Sie die OSS-Bucket-ACL auf 'private' und stellen Sie sicher, dass anonymen Benutzern keine öffentlichen Lese-/Schreibberechtigungen gewährt werden.",
		"es": "Configure el ACL del bucket OSS en 'private' y asegúrese de que no se otorguen permisos de lectura/escritura públicos a usuarios anónimos.",
		"fr": "Configurez l'ACL du bucket OSS sur 'private' et assurez-vous qu'aucune permission de lecture/écriture publique n'est accordée aux utilisateurs anonymes.",
		"pt": "Configure o ACL do bucket OSS como 'private' e garanta que nenhuma permissão de leitura/gravação pública seja concedida a usuários anônimos."
	},
	"resource_types": ["ALIYUN::OSS::Bucket"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Conceptual check for public access
	acl := helpers.get_property(resource, "AccessControlList", "private")
	acl != "private"
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AccessControlList"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
