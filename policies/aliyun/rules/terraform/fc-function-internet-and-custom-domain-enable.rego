package infraguard.rules.terraform.fc_function_internet_and_custom_domain_enable

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "fc-function-internet-and-custom-domain-enable",
	"severity": "medium",
	"name": {
		"en": "FC Service Internet Access with Custom Domain",
		"zh": "函数计算服务允许访问公网且绑定到自定义域名",
		"ja": "カスタムドメインを使用した FC サービスインターネットアクセス",
		"de": "FC-Service Internetzugang mit benutzerdefinierter Domäne",
		"es": "Acceso a Internet del Servicio FC con Dominio Personalizado",
		"fr": "Accès Internet au Service FC avec Domaine Personnalisé",
		"pt": "Acesso à Internet do Serviço FC com Domínio Personalizado"
	},
	"description": {
		"en": "FC services with internet access should be bound to custom domains for proper access control.",
		"zh": "函数计算服务在允许公网访问时绑定了自定义域名，视为合规。",
		"ja": "インターネットアクセスを持つ FC サービスは、適切なアクセス制御のためにカスタムドメインにバインドする必要があります。",
		"de": "FC-Services mit Internetzugang sollten an benutzerdefinierte Domänen gebunden werden, um ordnungsgemäße Zugriffskontrolle zu gewährleisten.",
		"es": "Los servicios FC con acceso a Internet deben estar vinculados a dominios personalizados para un control de acceso adecuado.",
		"fr": "Les services FC avec accès Internet doivent être liés à des domaines personnalisés pour un contrôle d'accès approprié.",
		"pt": "Os serviços FC com acesso à Internet devem estar vinculados a domínios personalizados para controle de acesso adequado."
	},
	"reason": {
		"en": "The FC service allows internet access but does not have custom domains configured.",
		"zh": "函数计算服务允许访问公网，但未配置自定义域名。",
		"ja": "FC サービスはインターネットアクセスを許可していますが、カスタムドメインが設定されていない可能性があります。",
		"de": "Der FC-Service erlaubt Internetzugang, hat aber möglicherweise keine benutzerdefinierten Domänen konfiguriert.",
		"es": "El servicio FC permite acceso a Internet pero puede no tener dominios personalizados configurados.",
		"fr": "Le service FC autorise l'accès Internet mais peut ne pas avoir de domaines personnalisés configurés.",
		"pt": "O serviço FC permite acesso à Internet, mas pode não ter domínios personalizados configurados."
	},
	"recommendation": {
		"en": "Configure custom domains for FC services that need internet access.",
		"zh": "为需要公网访问的函数计算服务配置自定义域名。",
		"ja": "インターネットアクセスが必要な FC サービスにカスタムドメインを設定します。",
		"de": "Konfigurieren Sie benutzerdefinierte Domänen für FC-Services, die Internetzugang benötigen.",
		"es": "Configure dominios personalizados para servicios FC que necesitan acceso a Internet.",
		"fr": "Configurez des domaines personnalisés pour les services FC qui ont besoin d'un accès Internet.",
		"pt": "Configure domínios personalizados para serviços FC que precisam de acesso à Internet."
	},
	"resource_types": ["alicloud_fc_service"],
	"iac_type": "terraform"
}

has_custom_domain_in_template if {
	tf.has_resource_type("alicloud_fc_custom_domain")
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_fc_service")
	tf.get_attribute(resource, "internet_access", false) == true
	not has_custom_domain_in_template
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_fc_service.%s", [name]),
		"violation_path": ["internet_access"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
