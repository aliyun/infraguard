package infraguard.rules.terraform.ram_user_has_specified_policy

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-user-has-specified-policy",
	"severity": "medium",
	"name": {
		"en": "RAM User Has Specified Policy",
		"zh": "RAM 用户及所属用户组绑定指定条件的权限策略",
		"ja": "RAM ユーザーに指定されたポリシーがある",
		"de": "RAM-Benutzer hat angegebene Richtlinie",
		"es": "El Usuario RAM Tiene Política Especificada",
		"fr": "L'Utilisateur RAM a une Politique Spécifiée",
		"pt": "O Usuário RAM Tem Política Especificada"
	},
	"description": {
		"en": "Ensures RAM users have at least one policy attached via alicloud_ram_user_policy_attachment.",
		"zh": "确保 RAM 用户通过 alicloud_ram_user_policy_attachment 绑定了至少一个权限策略。",
		"ja": "RAM ユーザーに alicloud_ram_user_policy_attachment を通じて少なくとも 1 つのポリシーがアタッチされていることを確認します。",
		"de": "Stellt sicher, dass RAM-Benutzer über alicloud_ram_user_policy_attachment mindestens eine Richtlinie angehängt haben.",
		"es": "Garantiza que los usuarios RAM tengan al menos una política adjunta mediante alicloud_ram_user_policy_attachment.",
		"fr": "Garantit que les utilisateurs RAM ont au moins une politique attachée via alicloud_ram_user_policy_attachment.",
		"pt": "Garante que os usuários RAM tenham pelo menos uma política anexada via alicloud_ram_user_policy_attachment."
	},
	"reason": {
		"en": "Proper policy attachment ensures users have necessary permissions.",
		"zh": "正确绑定策略可确保用户具有必要的权限。",
		"ja": "適切なポリシーのアタッチにより、ユーザーに必要な権限があることが保証されます。",
		"de": "Die ordnungsgemäße Anheftung von Richtlinien stellt sicher, dass Benutzer die erforderlichen Berechtigungen haben.",
		"es": "La adjunción adecuada de políticas garantiza que los usuarios tengan los permisos necesarios.",
		"fr": "L'attachement approprié des politiques garantit que les utilisateurs ont les permissions nécessaires.",
		"pt": "O anexo adequado de políticas garante que os usuários tenham as permissões necessárias."
	},
	"recommendation": {
		"en": "Add an alicloud_ram_user_policy_attachment resource to attach policies to the RAM user.",
		"zh": "添加 alicloud_ram_user_policy_attachment 资源为 RAM 用户绑定策略。",
		"ja": "alicloud_ram_user_policy_attachment リソースを追加して、RAM ユーザーにポリシーをアタッチします。",
		"de": "Fügen Sie eine alicloud_ram_user_policy_attachment-Ressource hinzu, um Richtlinien an den RAM-Benutzer anzuhängen.",
		"es": "Agregue un recurso alicloud_ram_user_policy_attachment para adjuntar políticas al usuario RAM.",
		"fr": "Ajoutez une ressource alicloud_ram_user_policy_attachment pour attacher des politiques à l'utilisateur RAM.",
		"pt": "Adicione um recurso alicloud_ram_user_policy_attachment para anexar políticas ao usuário RAM."
	},
	"resource_types": ["alicloud_ram_user"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_user")
	not tf.has_resource_type("alicloud_ram_user_policy_attachment")
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_user.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
