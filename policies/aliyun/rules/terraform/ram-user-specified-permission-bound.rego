package infraguard.rules.terraform.ram_user_specified_permission_bound

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-specified-permission-bound",
	"severity": "high",
	"name": {
		"en": "RAM User Specified Permission Bound",
		"zh": "RAM 用户未绑定指定的高危权限",
		"ja": "RAM ユーザー指定の権限バウンド",
		"de": "RAM-Benutzer Angegebene Berechtigungsgrenze",
		"es": "Límite de Permiso Especificado del Usuario RAM",
		"fr": "Limite de Permission Spécifiée de l'Utilisateur RAM",
		"pt": "Limite de Permissão Especificada do Usuário RAM"
	},
	"description": {
		"en": "Ensures RAM users do not have specified high-risk permissions bound.",
		"zh": "确保 RAM 用户绑定的权限策略配置中，不包含规则入参指定的高危权限配置。",
		"ja": "RAM ユーザーに指定された高リスク権限がバインドされていないことを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer keine angegebenen Hochrisiko-Berechtigungen gebunden haben.",
		"es": "Garantiza que los usuarios RAM no tengan permisos de alto riesgo especificados vinculados.",
		"fr": "Garantit que les utilisateurs RAM n'ont pas de permissions à haut risque spécifiées liées.",
		"pt": "Garante que os usuários RAM não tenham permissões de alto risco especificadas vinculadas."
	},
	"reason": {
		"en": "High-risk permissions can cause significant damage if misused.",
		"zh": "高危权限一旦被滥用可能造成重大损失。",
		"ja": "高リスク権限は誤用されると重大な損害を引き起こす可能性があります。",
		"de": "Hochrisiko-Berechtigungen können bei Missbrauch erheblichen Schaden verursachen.",
		"es": "Los permisos de alto riesgo pueden causar daños significativos si se usan mal.",
		"fr": "Les permissions à haut risque peuvent causer des dommages importants en cas d'abus.",
		"pt": "Permissões de alto risco podem causar danos significativos se mal utilizadas."
	},
	"recommendation": {
		"en": "Remove AdministratorAccess system policy from alicloud_ram_user_policy_attachment and restrict permissions to only what is necessary.",
		"zh": "从 alicloud_ram_user_policy_attachment 中移除 AdministratorAccess 系统策略，仅授予必要的权限。",
		"ja": "alicloud_ram_user_policy_attachment から AdministratorAccess システムポリシーを削除し、必要な権限のみに制限します。",
		"de": "Entfernen Sie die AdministratorAccess-Systemrichtlinie aus alicloud_ram_user_policy_attachment und beschränken Sie die Berechtigungen auf das Notwendige.",
		"es": "Elimine la política de sistema AdministratorAccess de alicloud_ram_user_policy_attachment y restrinja los permisos solo a lo necesario.",
		"fr": "Supprimez la politique système AdministratorAccess de alicloud_ram_user_policy_attachment et restreignez les permissions uniquement à ce qui est nécessaire.",
		"pt": "Remova a política de sistema AdministratorAccess de alicloud_ram_user_policy_attachment e restrinja as permissões apenas ao necessário."
	},
	"resource_types": ["alicloud_ram_user_policy_attachment"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_user_policy_attachment")
	policy_type := tf.get_attribute(resource, "policy_type", "")
	policy_type == "System"
	policy_name := tf.get_attribute(resource, "policy_name", "")
	policy_name == "AdministratorAccess"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_user_policy_attachment.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
