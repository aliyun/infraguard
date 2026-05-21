package infraguard.rules.terraform.oss_bucket_public_write_prohibited

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-public-write-prohibited",
	"severity": "high",
	"name": {
		"en": "OSS Bucket Public Write Prohibited",
		"zh": "OSS 存储空间 ACL 不开启公共写",
		"ja": "OSS バケットのパブリック書き込みが禁止",
		"de": "OSS-Bucket öffentliches Schreiben verboten",
		"es": "Escritura Pública de Bucket OSS Prohibida",
		"fr": "Écriture Publique de Bucket OSS Interdite",
		"pt": "Escrita Pública de Bucket OSS Proibida"
	},
	"description": {
		"en": "Ensures OSS bucket ACL does not allow public write access.",
		"zh": "确保 OSS 存储桶 ACL 不允许公共写入访问。",
		"ja": "OSS バケットはパブリック書き込みアクセスを許可すべきではありません。パブリック書き込みアクセスにより、誰でもバケット内のオブジェクトをアップロード、変更、または削除でき、重大なセキュリティリスクをもたらします。",
		"de": "OSS-Buckets sollten keinen öffentlichen Schreibzugriff zulassen. Öffentlicher Schreibzugriff ermöglicht es jedem, Objekte im Bucket hochzuladen, zu ändern oder zu löschen, was erhebliche Sicherheitsrisiken birgt.",
		"es": "Los buckets OSS no deben permitir acceso de escritura público. El acceso de escritura público permite a cualquiera cargar, modificar o eliminar objetos en el bucket, lo que plantea riesgos de seguridad significativos.",
		"fr": "Les buckets OSS ne doivent pas autoriser l'accès en écriture public. L'accès en écriture public permet à quiconque de télécharger, modifier ou supprimer des objets dans le bucket, ce qui pose des risques de sécurité importants.",
		"pt": "Buckets OSS não devem permitir acesso de escrita público. O acesso de escrita público permite que qualquer pessoa faça upload, modifique ou exclua objetos no bucket, o que representa riscos significativos de segurança."
	},
	"reason": {
		"en": "The OSS bucket ACL allows public write access.",
		"zh": "OSS 存储桶 ACL 允许公共写入访问。",
		"ja": "OSS バケットでパブリック書き込みアクセスが有効になっている（public-read-write ACL）ため、不正なユーザーがデータを変更または削除できます。",
		"de": "Der OSS-Bucket hat öffentlichen Schreibzugriff aktiviert (public-read-write ACL), was unbefugten Benutzern ermöglicht, Daten zu ändern oder zu löschen.",
		"es": "El bucket OSS tiene habilitado el acceso de escritura público (ACL public-read-write), lo que permite a usuarios no autorizados modificar o eliminar datos.",
		"fr": "Le bucket OSS a l'accès en écriture public activé (ACL public-read-write), ce qui permet aux utilisateurs non autorisés de modifier ou supprimer des données.",
		"pt": "O bucket OSS tem acesso de escrita público habilitado (ACL public-read-write), o que permite que usuários não autorizados modifiquem ou excluam dados."
	},
	"recommendation": {
		"en": "Set the bucket ACL to 'private' to prevent public write access.",
		"zh": "将存储桶 ACL 设置为 'private' 以防止公共写入访问。",
		"ja": "AccessControl プロパティを 'private' または 'public-read' に設定して、バケット ACL をプライベートまたはパブリック読み取りに変更します。",
		"de": "Ändern Sie die Bucket-ACL auf privat oder öffentlich-lesen, indem Sie die AccessControl-Eigenschaft auf 'private' oder 'public-read' setzen.",
		"es": "Cambie el ACL del bucket a privado o lectura pública estableciendo la propiedad AccessControl en 'private' o 'public-read'.",
		"fr": "Modifiez l'ACL du bucket en privé ou lecture publique en définissant la propriété AccessControl sur 'private' ou 'public-read'.",
		"pt": "Altere o ACL do bucket para privado ou leitura pública definindo a propriedade AccessControl como 'private' ou 'public-read'."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	acl := tf.get_attribute(resource, "acl", "private")
	not tf.is_unknown(acl)
	acl == "public-read-write"
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
