package infraguard.rules.aliyun.ram_user_activated_ak_quantity_check

import data.infraguard.helpers
import rego.v1

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
		"en": "Ensures RAM users do not have more than one active AccessKey.",
		"zh": "确保 RAM 用户激活的 AccessKey 数量不超过 1 个。",
		"ja": "RAM ユーザーが 1 つを超えるアクティブな AccessKey を持っていないことを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer nicht mehr als einen aktiven AccessKey haben.",
		"es": "Garantiza que los usuarios RAM no tengan más de una AccessKey activa.",
		"fr": "Garantit que les utilisateurs RAM n'ont pas plus d'une AccessKey active.",
		"pt": "Garante que usuários RAM não tenham mais de uma AccessKey ativa."
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
		"en": "Deactivate or remove unnecessary AccessKeys.",
		"zh": "禁用或移除不必要的 AccessKey。",
		"ja": "不要な AccessKey を無効化または削除します。",
		"de": "Deaktivieren oder entfernen Sie unnötige AccessKeys.",
		"es": "Desactive o elimine AccessKeys innecesarias.",
		"fr": "Désactivez ou supprimez les AccessKeys inutiles.",
		"pt": "Desative ou remova AccessKeys desnecessárias."
	},
	"resource_types": ["ALIYUN::RAM::User"]
}

# Cross-resource check: Count ALIYUN::RAM::AccessKey referencing this user
count_active_aks(user_logical_id) := count([name |
	some name, res in helpers.resources_by_type("ALIYUN::RAM::AccessKey")
	helpers.matches_resource_id(helpers.get_property(res, "UserName", ""), user_logical_id, "UserName")
	# Assuming it's active by default or has a status property
])

deny contains result if {
	some user_logical_id, resource in helpers.resources_by_type("ALIYUN::RAM::User")
	count_active_aks(user_logical_id) > 1
	result := {
		"id": rule_meta.id,
		"resource_id": user_logical_id,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
