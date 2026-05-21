package infraguard.rules.terraform.ots_instance_network_not_normal

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ots-instance-network-not-normal",
	"severity": "medium",
	"name": {
		"en": "OTS Restricted Network Type",
		"zh": "OTS 实例限制网络类型",
		"ja": "OTS 制限されたネットワークタイプ",
		"de": "OTS eingeschränkter Netzwerktyp",
		"es": "Tipo de Red Restringido OTS",
		"fr": "Type de Réseau Restreint OTS",
		"pt": "Tipo de Rede Restrito OTS"
	},
	"description": {
		"en": "OTS instances should not use unrestricted network access (Any). Use Vpc or ConsoleOrVpc instead.",
		"zh": "OTS 实例不应使用不受限制的网络访问（Any），应使用 Vpc 或 ConsoleOrVpc。",
		"ja": "OTS インスタンスは無制限のネットワークアクセス（Any）を使用すべきではありません。代わりに Vpc または ConsoleOrVpc を使用してください。",
		"de": "OTS-Instanzen sollten keinen uneingeschränkten Netzwerkzugriff (Any) verwenden. Verwenden Sie stattdessen Vpc oder ConsoleOrVpc.",
		"es": "Las instancias OTS no deben usar acceso de red sin restricciones (Any). Use Vpc o ConsoleOrVpc en su lugar.",
		"fr": "Les instances OTS ne doivent pas utiliser un accès réseau sans restriction (Any). Utilisez Vpc ou ConsoleOrVpc à la place.",
		"pt": "As instâncias OTS não devem usar acesso de rede irrestrito (Any). Use Vpc ou ConsoleOrVpc em vez disso."
	},
	"reason": {
		"en": "The OTS instance allows unrestricted network access (Any), which exposes the instance to public internet.",
		"zh": "OTS 实例允许不受限制的网络访问（Any），这会将实例暴露在公网中。",
		"ja": "OTS インスタンスは無制限のネットワークアクセス（Any）を許可しており、インスタンスがパブリックインターネットに公開されています。",
		"de": "Die OTS-Instanz erlaubt uneingeschränkten Netzwerkzugriff (Any), wodurch die Instanz dem öffentlichen Internet ausgesetzt wird.",
		"es": "La instancia OTS permite acceso de red sin restricciones (Any), lo que expone la instancia a Internet público.",
		"fr": "L'instance OTS autorise un accès réseau sans restriction (Any), ce qui expose l'instance à Internet public.",
		"pt": "A instância OTS permite acesso de rede irrestrito (Any), o que expõe a instância à Internet pública."
	},
	"recommendation": {
		"en": "Set accessed_by to 'Vpc' or 'ConsoleOrVpc' to restrict network access.",
		"zh": "将 accessed_by 设置为 'Vpc' 或 'ConsoleOrVpc' 以限制网络访问。",
		"ja": "ネットワークアクセスを制限するために accessed_by を 'Vpc' または 'ConsoleOrVpc' に設定します。",
		"de": "Setzen Sie accessed_by auf 'Vpc' oder 'ConsoleOrVpc', um den Netzwerkzugriff einzuschränken.",
		"es": "Establezca accessed_by en 'Vpc' o 'ConsoleOrVpc' para restringir el acceso de red.",
		"fr": "Définissez accessed_by sur 'Vpc' ou 'ConsoleOrVpc' pour restreindre l'accès réseau.",
		"pt": "Defina accessed_by como 'Vpc' ou 'ConsoleOrVpc' para restringir o acesso de rede."
	},
	"resource_types": ["alicloud_ots_instance"],
	"iac_type": "terraform"
}

is_restricted_network(resource) if {
	accessed_by := tf.get_attribute(resource, "accessed_by", "")
	not tf.is_unknown(accessed_by)
	accessed_by != "Any"
	accessed_by != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ots_instance")
	not is_restricted_network(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ots_instance.%s", [name]),
		"violation_path": ["accessed_by"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
