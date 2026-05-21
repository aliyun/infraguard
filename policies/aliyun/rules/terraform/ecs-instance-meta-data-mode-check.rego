package infraguard.rules.terraform.ecs_instance_meta_data_mode_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-instance-meta-data-mode-check",
	"severity": "medium",
	"name": {
		"en": "ECS instance metadata access uses security-enhanced mode (IMDSv2)",
		"zh": "访问 ECS 实例元数据时强制使用加固模式",
		"ja": "ECS インスタンスメタデータアクセスがセキュリティ強化モード（IMDSv2）を使用",
		"de": "ECS-Instanz-Metadatenzugriff verwendet sicherheitsverbesserten Modus (IMDSv2)",
		"es": "El acceso a metadatos de instancia ECS usa modo de seguridad mejorado (IMDSv2)",
		"fr": "L'accès aux métadonnées d'instance ECS utilise le mode de sécurité renforcé (IMDSv2)",
		"pt": "Acesso a metadados de instância ECS usa modo de segurança aprimorado (IMDSv2)"
	},
	"description": {
		"en": "When accessing ECS instance metadata, security-enhanced mode (IMDSv2) is enforced, considered compliant. Instances associated with ACK clusters are not applicable.",
		"zh": "访问 ECS 实例元数据时强制使用加固模式，视为合规。ACK 集群关联的实例视为不适用。",
		"ja": "ECS インスタンスメタデータにアクセスする際、セキュリティ強化モード（IMDSv2）が適用され、準拠と見なされます。ACK クラスタに関連付けられたインスタンスは適用されません。",
		"de": "Beim Zugriff auf ECS-Instanz-Metadaten wird der sicherheitsverbesserte Modus (IMDSv2) erzwungen, wird als konform betrachtet. Mit ACK-Clustern verbundene Instanzen sind nicht anwendbar.",
		"es": "Al acceder a metadatos de instancia ECS, se aplica el modo de seguridad mejorado (IMDSv2), considerado conforme. Las instancias asociadas con clústeres ACK no son aplicables.",
		"fr": "Lors de l'accès aux métadonnées d'instance ECS, le mode de sécurité renforcé (IMDSv2) est appliqué, considéré comme conforme. Les instances associées aux clusters ACK ne sont pas applicables.",
		"pt": "Ao acessar metadados de instância ECS, o modo de segurança aprimorado (IMDSv2) é aplicado, considerado conforme. Instâncias associadas a clusters ACK não são aplicáveis."
	},
	"reason": {
		"en": "ECS instance metadata is accessible without security-enhanced mode (IMDSv1)",
		"zh": "ECS 实例元数据可在未启用加固模式(IMDSv1)的情况下访问",
		"ja": "ECS インスタンスメタデータはセキュリティ強化モード（IMDSv1）なしでアクセス可能",
		"de": "ECS-Instanz-Metadaten sind ohne sicherheitsverbesserten Modus (IMDSv1) zugänglich",
		"es": "Los metadatos de instancia ECS son accesibles sin modo de seguridad mejorado (IMDSv1)",
		"fr": "Les métadonnées d'instance ECS sont accessibles sans mode de sécurité renforcé (IMDSv1)",
		"pt": "Metadados de instância ECS são acessíveis sem modo de segurança aprimorado (IMDSv1)"
	},
	"recommendation": {
		"en": "Set HttpEndpoint to 'enabled' and HttpTokens to 'required' to enforce IMDSv2",
		"zh": "将 HttpEndpoint 设置为 'enabled'，并将 HttpTokens 设置为 'required' 以强制使用 IMDSv2",
		"ja": "IMDSv2 を適用するために、HttpEndpoint を 'enabled' に設定し、HttpTokens を 'required' に設定します",
		"de": "Setzen Sie HttpEndpoint auf 'enabled' und HttpTokens auf 'required', um IMDSv2 zu erzwingen",
		"es": "Establezca HttpEndpoint en 'enabled' y HttpTokens en 'required' para aplicar IMDSv2",
		"fr": "Définissez HttpEndpoint sur 'enabled' et HttpTokens sur 'required' pour appliquer IMDSv2",
		"pt": "Defina HttpEndpoint como 'enabled' e HttpTokens como 'required' para aplicar IMDSv2"
	},
	"resource_types": ["alicloud_instance"],
	"iac_type": "terraform"
}

violation_for(name) := {
	"id": rule_meta.id,
	"resource_id": sprintf("alicloud_instance.%s", [name]),
	"meta": {
		"severity": rule_meta.severity,
		"reason": rule_meta.reason,
		"recommendation": rule_meta.recommendation,
	},
}

metadata_attr(resource, attr, default_value) := value if {
	options := tf.get_attribute(resource, "metadata_options", {})
	not tf.is_unknown(options)
	value := options[attr]
	value != null
} else := default_value

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	http_endpoint := metadata_attr(resource, "http_endpoint", "enabled")
	not tf.is_unknown(http_endpoint)
	http_endpoint == "disabled"
	violation := violation_for(name)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	http_endpoint := metadata_attr(resource, "http_endpoint", "enabled")
	not tf.is_unknown(http_endpoint)
	http_endpoint != "disabled"
	http_tokens := metadata_attr(resource, "http_tokens", "optional")
	not tf.is_unknown(http_tokens)
	http_tokens == "optional"
	violation := violation_for(name)
}
