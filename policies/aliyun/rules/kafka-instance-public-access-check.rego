package infraguard.rules.aliyun.kafka_instance_public_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "kafka-instance-public-access-check",
	"name": {
		"en": "Kafka Public Access Disabled",
		"zh": "Kafka 实例禁用公网访问",
		"ja": "Kafka パブリックアクセスが無効",
		"de": "Kafka Öffentlicher Zugriff deaktiviert",
		"es": "Acceso Público de Kafka Deshabilitado",
		"fr": "Accès Public Kafka Désactivé",
		"pt": "Acesso Público do Kafka Desabilitado",
	},
	"severity": "high",
	"description": {
		"en": "Ensures Kafka instances do not have public network access.",
		"zh": "确保 Kafka 实例未开启公网访问。",
		"ja": "Kafka インスタンスにパブリックネットワークアクセスがないことを確認します。",
		"de": "Stellt sicher, dass Kafka-Instanzen keinen öffentlichen Netzwerkzugriff haben.",
		"es": "Garantiza que las instancias Kafka no tengan acceso a la red pública.",
		"fr": "Garantit que les instances Kafka n'ont pas d'accès réseau public.",
		"pt": "Garante que as instâncias Kafka não tenham acesso à rede pública.",
	},
	"reason": {
		"en": "Exposing Kafka to the public internet is a significant security risk.",
		"zh": "将 Kafka 暴露在公网会带来重大的安全风险。",
		"ja": "Kafka をパブリックインターネットに公開することは、重大なセキュリティリスクです。",
		"de": "Das Aussetzen von Kafka im öffentlichen Internet ist ein erhebliches Sicherheitsrisiko.",
		"es": "Exponer Kafka a Internet público es un riesgo de seguridad significativo.",
		"fr": "Exposer Kafka à Internet public constitue un risque de sécurité important.",
		"pt": "Expor Kafka à Internet pública é um risco de segurança significativo.",
	},
	"recommendation": {
		"en": "Disable the public endpoint for the Kafka instance.",
		"zh": "禁用 Kafka 实例的公网端点。",
		"ja": "Kafka インスタンスのパブリックエンドポイントを無効にします。",
		"de": "Deaktivieren Sie den öffentlichen Endpunkt für die Kafka-Instanz.",
		"es": "Deshabilite el punto final público para la instancia Kafka.",
		"fr": "Désactivez le point de terminaison public pour l'instance Kafka.",
		"pt": "Desabilite o ponto de extremidade público para a instância Kafka.",
	},
	"resource_types": ["ALIYUN::KAFKA::Instance"],
}

is_compliant(resource) if {
	# In ROS, check DeployType or similar properties
	# 4: VPC, 5: Public
	type := helpers.get_property(resource, "DeployType", 4)
	type != 5
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::KAFKA::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DeployType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
