package infraguard.rules.terraform.kafka_instance_public_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "kafka-instance-public-access-check",
	"severity": "high",
	"name": {
		"en": "Kafka Instance Public Access Check",
		"zh": "Kafka 实例公网访问检查",
		"ja": "Kafka インスタンスのパブリックアクセスチェック",
		"de": "Kafka-Instanz Öffentlicher Zugriff Prüfung",
		"es": "Verificación de Acceso Público de Instancia Kafka",
		"fr": "Vérification de l'Accès Public de l'Instance Kafka",
		"pt": "Verificação de Acesso Público da Instância Kafka"
	},
	"description": {
		"en": "Kafka instances should not be deployed with public access (deploy_type 5). Use VPC-only deployment (deploy_type 4) to restrict access to internal networks.",
		"zh": "Kafka 实例不应使用公网部署方式（deploy_type 为 5）。应使用 VPC 部署方式（deploy_type 为 4）以限制仅内网访问。",
		"ja": "Kafka インスタンスはパブリックアクセス（deploy_type 5）で展開すべきではありません。VPC のみの展開（deploy_type 4）を使用して内部ネットワークへのアクセスを制限します。",
		"de": "Kafka-Instanzen sollten nicht mit öffentlichem Zugriff (deploy_type 5) bereitgestellt werden. Verwenden Sie VPC-only-Bereitstellung (deploy_type 4), um den Zugriff auf interne Netzwerke zu beschränken.",
		"es": "Las instancias Kafka no deben implementarse con acceso público (deploy_type 5). Use implementación solo VPC (deploy_type 4) para restringir el acceso a redes internas.",
		"fr": "Les instances Kafka ne doivent pas être déployées avec accès public (deploy_type 5). Utilisez le déploiement VPC uniquement (deploy_type 4) pour restreindre l'accès aux réseaux internes.",
		"pt": "Instâncias Kafka não devem ser implantadas com acesso público (deploy_type 5). Use implantação somente VPC (deploy_type 4) para restringir acesso a redes internas."
	},
	"reason": {
		"en": "The Kafka instance is deployed with public access enabled (deploy_type = 5), exposing it to the internet.",
		"zh": "Kafka 实例以公网访问方式部署（deploy_type = 5），暴露在互联网中。",
		"ja": "Kafka インスタンスがパブリックアクセス有効（deploy_type = 5）で展開されており、インターネットに公開されています。",
		"de": "Die Kafka-Instanz ist mit öffentlichem Zugriff (deploy_type = 5) bereitgestellt und dem Internet ausgesetzt.",
		"es": "La instancia Kafka está implementada con acceso público habilitado (deploy_type = 5), exponiéndola a internet.",
		"fr": "L'instance Kafka est déployée avec accès public activé (deploy_type = 5), l'exposant à Internet.",
		"pt": "A instância Kafka está implantada com acesso público habilitado (deploy_type = 5), expondo-a à internet."
	},
	"recommendation": {
		"en": "Set deploy_type to 4 (VPC only) to disable public access and restrict the Kafka instance to internal network access.",
		"zh": "将 deploy_type 设置为 4（仅 VPC）以禁用公网访问，限制 Kafka 实例仅内网访问。",
		"ja": "deploy_type を 4（VPC のみ）に設定して、パブリックアクセスを無効にし、Kafka インスタンスを内部ネットワークアクセスに制限します。",
		"de": "Setzen Sie deploy_type auf 4 (nur VPC), um den öffentlichen Zugriff zu deaktivieren und die Kafka-Instanz auf internen Netzwerkzugriff zu beschränken.",
		"es": "Establezca deploy_type en 4 (solo VPC) para deshabilitar el acceso público y restringir la instancia Kafka al acceso de red interna.",
		"fr": "Définissez deploy_type sur 4 (VPC uniquement) pour désactiver l'accès public et restreindre l'instance Kafka à l'accès réseau interne.",
		"pt": "Defina deploy_type como 4 (somente VPC) para desabilitar acesso público e restringir a instância Kafka ao acesso de rede interna."
	},
	"resource_types": ["alicloud_alikafka_instance"],
	"iac_type": "terraform"
}

is_public_access(resource) if {
	deploy_type := tf.get_attribute(resource, "deploy_type", 4)
	not tf.is_unknown(deploy_type)
	deploy_type == 5
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_alikafka_instance")
	is_public_access(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_alikafka_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
