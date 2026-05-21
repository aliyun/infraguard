package infraguard.rules.terraform.ram_user_no_has_specified_policy

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-no-has-specified-policy",
	"severity": "high",
	"name": {
		"en": "RAM User No Specified Policy",
		"zh": "RAM 用户及所属用户组未绑定指定条件的权限策略",
		"ja": "RAM ユーザーに指定されたポリシーなし",
		"de": "RAM-Benutzer keine angegebene Richtlinie",
		"es": "Usuario RAM Sin Política Especificada",
		"fr": "Utilisateur RAM Sans Politique Spécifiée",
		"pt": "Usuário RAM Sem Política Especificada"
	},
	"description": {
		"en": "Ensures RAM users do not have specified risky policies attached.",
		"zh": "确保 RAM 用户未绑定符合参数条件的高危权限策略。",
		"ja": "RAM ユーザーに指定されたリスクのあるポリシーが添付されていないことを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer keine angegebenen riskanten Richtlinien angehängt haben.",
		"es": "Garantiza que los usuarios RAM no tengan políticas riesgosas especificadas adjuntas.",
		"fr": "Garantit que les utilisateurs RAM n'ont pas de politiques risquées spécifiées attachées.",
		"pt": "Garante que os usuários RAM não tenham políticas arriscadas especificadas anexadas."
	},
	"reason": {
		"en": "Risky policies increase the attack surface.",
		"zh": "高危策略会增加攻击面。",
		"ja": "リスクのあるポリシーは攻撃面を増加させます。",
		"de": "Riskante Richtlinien erhöhen die Angriffsfläche.",
		"es": "Las políticas riesgosas aumentan la superficie de ataque.",
		"fr": "Les politiques risquées augmentent la surface d'attaque.",
		"pt": "Políticas arriscadas aumentam a superfície de ataque."
	},
	"recommendation": {
		"en": "Remove AdministratorAccess policy from the alicloud_ram_user_policy_attachment and use least privilege alternatives.",
		"zh": "从 alicloud_ram_user_policy_attachment 中移除 AdministratorAccess 策略，使用最小权限的替代方案。",
		"ja": "alicloud_ram_user_policy_attachment から AdministratorAccess ポリシーを削除し、最小権限の代替案を使用します。",
		"de": "Entfernen Sie die AdministratorAccess-Richtlinie aus alicloud_ram_user_policy_attachment und verwenden Sie Alternativen mit geringsten Berechtigungen.",
		"es": "Elimine la política AdministratorAccess de alicloud_ram_user_policy_attachment y use alternativas de menor privilegio.",
		"fr": "Supprimez la politique AdministratorAccess de alicloud_ram_user_policy_attachment et utilisez des alternatives à privilèges minimaux.",
		"pt": "Remova a política AdministratorAccess de alicloud_ram_user_policy_attachment e use alternativas de menor privilégio."
	},
	"resource_types": ["alicloud_ram_user_policy_attachment"],
	"iac_type": "terraform"
}

risky_policies := {"AdministratorAccess", "*:*", "*"}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_user_policy_attachment")
	policy_name := tf.get_attribute(resource, "policy_name", "")
	not tf.is_unknown(policy_name)
	policy_name in risky_policies
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
