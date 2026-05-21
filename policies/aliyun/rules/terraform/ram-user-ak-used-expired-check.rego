package infraguard.rules.terraform.ram_user_ak_used_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Ensures that RAM user AccessKeys are in Active status.",
		"zh": "确保 RAM 用户 AccessKey 处于启用状态。",
		"ja": "RAM ユーザー AccessKey がアクティブ状態であることを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer AccessKeys im aktiven Status sind.",
		"es": "Garantiza que las AccessKeys de usuario RAM estén en estado Activo.",
		"fr": "Garantit que les AccessKeys d'utilisateur RAM sont en état Actif.",
		"pt": "Garante que as AccessKeys de usuário RAM estejam em status Ativo."
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
		"en": "Ensure the AccessKey status is set to Active, or remove unused AccessKeys.",
		"zh": "确保 AccessKey 的 status 设置为 Active，或删除未使用的 AccessKey。",
		"ja": "AccessKey の status を Active に設定するか、未使用の AccessKey を削除します。",
		"de": "Stellen Sie sicher, dass der AccessKey-Status auf Active gesetzt ist, oder entfernen Sie nicht verwendete AccessKeys.",
		"es": "Asegúrese de que el estado de AccessKey esté configurado como Active, o elimine AccessKeys no utilizadas.",
		"fr": "Assurez-vous que le statut de l'AccessKey est défini sur Active, ou supprimez les AccessKeys non utilisées.",
		"pt": "Certifique-se de que o status da AccessKey esteja definido como Active, ou remova AccessKeys não utilizadas."
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
