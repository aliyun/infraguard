package infraguard.rules.terraform.maxcompute_project_ip_whitelist_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "maxcompute-project-ip-whitelist-enabled",
	"severity": "high",
	"name": {
		"en": "MaxCompute Project IP Whitelist Enabled",
		"zh": "MaxCompute 项目已配置 IP 白名单",
		"ja": "MaxCompute プロジェクト IP ホワイトリストが有効",
		"de": "MaxCompute-Projekt IP-Whitelist aktiviert",
		"es": "Lista Blanca de IP del Proyecto MaxCompute Habilitada",
		"fr": "Liste Blanche IP du Projet MaxCompute Activée",
		"pt": "Lista Branca de IP do Projeto MaxCompute Habilitada"
	},
	"description": {
		"en": "Ensures MaxCompute projects have IP whitelist configured to restrict access.",
		"zh": "确保 MaxCompute 项目已配置 IP 白名单以限制访问。",
		"ja": "MaxCompute プロジェクトでアクセスを制限するために IP ホワイトリストが設定されていることを確認します。",
		"de": "Stellt sicher, dass MaxCompute-Projekte eine IP-Whitelist konfiguriert haben, um den Zugriff einzuschränken.",
		"es": "Garantiza que los proyectos MaxCompute tengan lista blanca de IP configurada para restringir el acceso.",
		"fr": "Garantit que les projets MaxCompute ont une liste blanche IP configurée pour restreindre l'accès.",
		"pt": "Garante que os projetos MaxCompute tenham lista branca de IP configurada para restringir acesso."
	},
	"reason": {
		"en": "The MaxCompute project does not have an IP whitelist configured, allowing unrestricted network access.",
		"zh": "MaxCompute 项目未配置 IP 白名单，允许不受限制的网络访问。",
		"ja": "MaxCompute プロジェクトに IP ホワイトリストが設定されておらず、無制限のネットワークアクセスが許可されています。",
		"de": "Das MaxCompute-Projekt hat keine IP-Whitelist konfiguriert, was uneingeschränkten Netzwerkzugriff ermöglicht.",
		"es": "El proyecto MaxCompute no tiene una lista blanca de IP configurada, permitiendo acceso de red sin restricciones.",
		"fr": "Le projet MaxCompute n'a pas de liste blanche IP configurée, permettant un accès réseau sans restriction.",
		"pt": "O projeto MaxCompute não tem lista branca de IP configurada, permitindo acesso de rede irrestrito."
	},
	"recommendation": {
		"en": "Configure an IP whitelist on the MaxCompute project by setting ip_white_list to restrict network access.",
		"zh": "通过设置 ip_white_list 来配置 MaxCompute 项目的 IP 白名单以限制网络访问。",
		"ja": "ip_white_list を設定して MaxCompute プロジェクトの IP ホワイトリストを設定し、ネットワークアクセスを制限します。",
		"de": "Konfigurieren Sie eine IP-Whitelist im MaxCompute-Projekt, indem Sie ip_white_list setzen, um den Netzwerkzugriff einzuschränken.",
		"es": "Configure una lista blanca de IP en el proyecto MaxCompute configurando ip_white_list para restringir el acceso de red.",
		"fr": "Configurez une liste blanche IP sur le projet MaxCompute en définissant ip_white_list pour restreindre l'accès réseau.",
		"pt": "Configure uma lista branca de IP no projeto MaxCompute definindo ip_white_list para restringir acesso de rede."
	},
	"resource_types": ["alicloud_maxcompute_project"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_maxcompute_project")
	ip_white_list := tf.get_attribute(resource, "ip_white_list", "")
	not tf.is_unknown(ip_white_list)
	ip_white_list == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_maxcompute_project.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
