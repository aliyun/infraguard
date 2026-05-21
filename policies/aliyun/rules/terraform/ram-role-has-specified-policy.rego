package infraguard.rules.terraform.ram_role_has_specified_policy

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ram-role-has-specified-policy",
	"severity": "medium",
	"name": {
		"en": "RAM Role Has Specified Policy",
		"zh": "RAM 角色绑定指定策略检测",
		"ja": "RAM ロールに指定されたポリシーがある",
		"de": "RAM-Rolle hat angegebene Richtlinie",
		"es": "El Rol RAM Tiene Política Especificada",
		"fr": "Le Rôle RAM a une Politique Spécifiée",
		"pt": "Função RAM Tem Política Especificada"
	},
	"description": {
		"en": "Ensures RAM roles have the specified policies attached.",
		"zh": "确保 RAM 角色绑定了符合参数条件的权限策略。",
		"ja": "RAM ロールに指定されたポリシーがアタッチされていることを確認します。",
		"de": "Stellt sicher, dass RAM-Rollen die angegebenen Richtlinien angehängt haben.",
		"es": "Garantiza que los roles RAM tengan las políticas especificadas adjuntas.",
		"fr": "Garantit que les rôles RAM ont les politiques spécifiées attachées.",
		"pt": "Garante que as funções RAM tenham as políticas especificadas anexadas."
	},
	"reason": {
		"en": "Proper policy attachment ensures roles have necessary permissions.",
		"zh": "正确绑定策略可确保角色具有必要的权限。",
		"ja": "適切なポリシーのアタッチにより、ロールに必要な権限があることが保証されます。",
		"de": "Die ordnungsgemäße Anheftung von Richtlinien stellt sicher, dass Rollen die erforderlichen Berechtigungen haben.",
		"es": "La adjunción adecuada de políticas garantiza que los roles tengan los permisos necesarios.",
		"fr": "L'attachement approprié des politiques garantit que les rôles ont les permissions nécessaires.",
		"pt": "O anexo adequado de políticas garante que as funções tenham as permissões necessárias."
	},
	"recommendation": {
		"en": "Add an alicloud_ram_role_policy_attachment resource to attach a policy to the role.",
		"zh": "添加 alicloud_ram_role_policy_attachment 资源以向角色绑定策略。",
		"ja": "alicloud_ram_role_policy_attachment リソースを追加して、ロールにポリシーをアタッチします。",
		"de": "Fügen Sie eine alicloud_ram_role_policy_attachment-Ressource hinzu, um eine Richtlinie an die Rolle anzuhängen.",
		"es": "Agregue un recurso alicloud_ram_role_policy_attachment para adjuntar una política al rol.",
		"fr": "Ajoutez une ressource alicloud_ram_role_policy_attachment pour attacher une politique au rôle.",
		"pt": "Adicione um recurso alicloud_ram_role_policy_attachment para anexar uma política à função."
	},
	"resource_types": ["alicloud_ram_role"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ram_role")
	not tf.has_resource_type("alicloud_ram_role_policy_attachment")
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ram_role.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
