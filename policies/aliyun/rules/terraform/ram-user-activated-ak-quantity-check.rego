package infraguard.rules.terraform.ram_user_activated_ak_quantity_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-activated-ak-quantity-check",
	"severity": "medium",
	"name": {
		"en": "RAM User Active AK Quantity Check",
		"zh": "RAM 用户激活 AccessKey 数量核查",
		"ja": "RAM ユーザーのアクティブ AccessKey 数量チェック",
		"de": "RAM-Benutzer aktive AK-Mengenprüfung",
		"es": "Verificación de Cantidad de AK Activo de Usuario RAM",
		"fr": "Vérification de la Quantité d'AK Actif d'Utilisateur RAM",
		"pt": "Verificação de Quantidade de AK Ativo de Usuário RAM"
	},
	"description": {
		"en": "Ensures RAM access keys have an active status.",
		"zh": "确保 RAM AccessKey 状态为激活。",
		"ja": "RAM アクセスキーがアクティブな状態であることを確認します。",
		"de": "Stellt sicher, dass RAM-Zugriffsschlüssel einen aktiven Status haben.",
		"es": "Garantiza que las claves de acceso RAM tengan un estado activo.",
		"fr": "Garantit que les clés d'accès RAM ont un statut actif.",
		"pt": "Garante que as chaves de acesso RAM tenham um status ativo."
	},
	"reason": {
		"en": "Limiting active AccessKeys reduces the potential impact of a credential leak.",
		"zh": "限制激活的 AccessKey 数量可降低凭据泄露的潜在危害。",
		"ja": "アクティブな AccessKey を制限することで、認証情報漏洩の潜在的な影響を低減します。",
		"de": "Die Begrenzung aktiver AccessKeys reduziert die potenzielle Auswirkung eines Anmeldeinformationslecks.",
		"es": "Limitar las AccessKeys activas reduce el impacto potencial de una fuga de credenciales.",
		"fr": "Limiter les AccessKeys actives réduit l'impact potentiel d'une fuite d'identifiants.",
		"pt": "Limitar AccessKeys ativas reduz o impacto potencial de um vazamento de credenciais."
	},
	"recommendation": {
		"en": "Set the status attribute to 'Active' on alicloud_ram_access_key resources, or remove inactive keys.",
		"zh": "在 alicloud_ram_access_key 资源上将 status 属性设置为 'Active'，或移除不活跃的密钥。",
		"ja": "alicloud_ram_access_key リソースで status 属性を 'Active' に設定するか、非アクティブなキーを削除します。",
		"de": "Setzen Sie das status-Attribut auf 'Active' bei alicloud_ram_access_key-Ressourcen oder entfernen Sie inaktive Schlüssel.",
		"es": "Establezca el atributo status en 'Active' en los recursos alicloud_ram_access_key, o elimine las claves inactivas.",
		"fr": "Définissez l'attribut status sur 'Active' pour les ressources alicloud_ram_access_key, ou supprimez les clés inactives.",
		"pt": "Defina o atributo status como 'Active' nos recursos alicloud_ram_access_key, ou remova chaves inativas."
	},
	"resource_types": ["alicloud_ram_access_key"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_access_key")
	status := tf.get_attribute(resource, "status", "Active")
	status != "Active"
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
