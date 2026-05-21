package infraguard.rules.terraform.ram_user_ak_create_date_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-ak-create-date-expired-check",
	"severity": "medium",
	"name": {
		"en": "RAM User AccessKey Creation Date Expired Check",
		"zh": "RAM 用户 AccessKey 创建时间到期检测",
		"ja": "RAM ユーザー AccessKey 作成日の有効期限チェック",
		"de": "RAM-Benutzer AccessKey Erstellungsdatum Ablaufprüfung",
		"es": "Verificación de Expiración de Fecha de Creación de AccessKey de Usuario RAM",
		"fr": "Vérification d'Expiration de la Date de Création d'AccessKey d'Utilisateur RAM",
		"pt": "Verificação de Expiração de Data de Criação de AccessKey de Usuário RAM"
	},
	"description": {
		"en": "Ensures that RAM user AccessKeys are properly managed with secure storage.",
		"zh": "确保 RAM 用户 AccessKey 通过安全存储进行妥善管理。",
		"ja": "RAM ユーザー AccessKey が安全なストレージで適切に管理されていることを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer AccessKeys mit sicherer Speicherung ordnungsgemäß verwaltet werden.",
		"es": "Garantiza que las AccessKeys de usuario RAM estén correctamente gestionadas con almacenamiento seguro.",
		"fr": "Garantit que les AccessKeys d'utilisateur RAM sont correctement gérées avec un stockage sécurisé.",
		"pt": "Garante que as AccessKeys de usuário RAM sejam gerenciadas adequadamente com armazenamento seguro."
	},
	"reason": {
		"en": "Regularly rotating AccessKeys reduces the risk of long-term credential leakage.",
		"zh": "定期轮换 AccessKey 可降低凭证长期泄露的风险。",
		"ja": "AccessKey を定期的にローテーションすることで、長期的な認証情報の漏洩リスクを低減します。",
		"de": "Die regelmäßige Rotation von AccessKeys reduziert das Risiko langfristiger Anmeldeinformationslecks.",
		"es": "Rotar AccessKeys regularmente reduce el riesgo de fuga de credenciales a largo plazo.",
		"fr": "La rotation régulière des AccessKeys réduit le risque de fuite d'identifiants à long terme.",
		"pt": "Rotacionar AccessKeys regularmente reduz o risco de vazamento de credenciais a longo prazo."
	},
	"recommendation": {
		"en": "Set the secret_file attribute on alicloud_ram_access_key resources to ensure keys are stored securely.",
		"zh": "在 alicloud_ram_access_key 资源上设置 secret_file 属性以确保密钥被安全存储。",
		"ja": "alicloud_ram_access_key リソースで secret_file 属性を設定して、キーが安全に保存されるようにします。",
		"de": "Setzen Sie das secret_file-Attribut auf alicloud_ram_access_key-Ressourcen, um sicherzustellen, dass Schlüssel sicher gespeichert werden.",
		"es": "Establezca el atributo secret_file en los recursos alicloud_ram_access_key para asegurar que las claves se almacenen de forma segura.",
		"fr": "Définissez l'attribut secret_file sur les ressources alicloud_ram_access_key pour garantir que les clés sont stockées en toute sécurité.",
		"pt": "Defina o atributo secret_file nos recursos alicloud_ram_access_key para garantir que as chaves sejam armazenadas com segurança."
	},
	"resource_types": ["alicloud_ram_access_key"],
	"iac_type": "terraform"
}

is_compliant(_resource) := true

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_access_key")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_access_key.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
