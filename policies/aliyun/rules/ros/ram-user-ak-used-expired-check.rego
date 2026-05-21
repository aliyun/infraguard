package infraguard.rules.aliyun.ram_user_ak_used_expired_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ram-user-ak-used-expired-check",
	"severity": "medium",
	"name": {
		"en": "RAM User AccessKey Last Used Date Check",
		"zh": "RAM 用户 AccessKey 最后使用时间检测",
		"ja": "RAM ユーザー AccessKey 最終使用日チェック",
		"de": "RAM-Benutzer AccessKey letztes Verwendungsdatum-Prüfung",
		"es": "Verificación de Fecha de Último Uso de AccessKey de Usuario RAM",
		"fr": "Vérification de la Date de Dernière Utilisation d'AccessKey d'Utilisateur RAM",
		"pt": "Verificação de Data de Último Uso de AccessKey de Usuário RAM"
	},
	"description": {
		"en": "Ensures that RAM user AccessKeys have been used within the specified number of days.",
		"zh": "确保 RAM 用户 AccessKey 在指定天数内有使用记录。",
		"ja": "RAM ユーザー AccessKey が指定された日数以内に使用されていることを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer AccessKeys innerhalb der angegebenen Anzahl von Tagen verwendet wurden.",
		"es": "Garantiza que las AccessKeys de usuario RAM se hayan utilizado dentro del número especificado de días.",
		"fr": "Garantit que les AccessKeys d'utilisateur RAM ont été utilisées dans le nombre de jours spécifié.",
		"pt": "Garante que as AccessKeys de usuário RAM tenham sido usadas dentro do número especificado de dias."
	},
	"reason": {
		"en": "Unused AccessKeys should be deactivated or deleted to reduce the attack surface.",
		"zh": "应停用或删除未使用的 AccessKey，以减少攻击面。",
		"ja": "未使用の AccessKey は攻撃面を減らすために無効化または削除する必要があります。",
		"de": "Nicht verwendete AccessKeys sollten deaktiviert oder gelöscht werden, um die Angriffsfläche zu reduzieren.",
		"es": "Las AccessKeys no utilizadas deben desactivarse o eliminarse para reducir la superficie de ataque.",
		"fr": "Les AccessKeys non utilisées doivent être désactivées ou supprimées pour réduire la surface d'attaque.",
		"pt": "AccessKeys não utilizadas devem ser desativadas ou excluídas para reduzir a superfície de ataque."
	},
	"recommendation": {
		"en": "Deactivate or delete unused RAM user AccessKeys.",
		"zh": "停用或删除未使用的 RAM 用户 AccessKey。",
		"ja": "未使用の RAM ユーザー AccessKey を無効化または削除します。",
		"de": "Deaktivieren oder löschen Sie nicht verwendete RAM-Benutzer AccessKeys.",
		"es": "Desactive o elimine AccessKeys de usuario RAM no utilizadas.",
		"fr": "Désactivez ou supprimez les AccessKeys d'utilisateur RAM non utilisées.",
		"pt": "Desative ou exclua AccessKeys de usuário RAM não utilizadas."
	},
	"resource_types": ["ALIYUN::RAM::AccessKey"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RAM::AccessKey")

	# Conceptual check for last used date
	helpers.has_property(resource, "LastUsedDate")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LastUsedDate"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
