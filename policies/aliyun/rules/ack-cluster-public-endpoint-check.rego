package infraguard.rules.aliyun.ack_cluster_public_endpoint_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ack-cluster-public-endpoint-check",
	"name": {
		"en": "ACK Cluster Public Endpoint Check",
		"zh": "ACK 集群未设置公网连接端点",
		"ja": "ACK クラスタのパブリックエンドポイントチェック",
		"de": "ACK-Cluster öffentlicher Endpunkt-Prüfung",
		"es": "Verificación de Endpoint Público del Cluster ACK",
		"fr": "Vérification de l'Endpoint Public du Cluster ACK",
		"pt": "Verificação de Endpoint Público do Cluster ACK",
	},
	"severity": "high",
	"description": {
		"en": "ACK clusters should not have a public endpoint set, or the associated SLB listener should have ACL enabled.",
		"zh": "ACK 集群未设置公网连接端点，或关联的 SLB 的监听开启 acl 访问控制，视为合规。",
		"ja": "ACK クラスタはパブリックエンドポイントを設定しないか、関連する SLB リスナーで ACL を有効にする必要があります。",
		"de": "ACK-Cluster sollten keinen öffentlichen Endpunkt gesetzt haben, oder der zugehörige SLB-Listener sollte ACL aktiviert haben.",
		"es": "Los clústeres ACK no deben tener un endpoint público configurado, o el listener SLB asociado debe tener ACL habilitado.",
		"fr": "Les clusters ACK ne doivent pas avoir d'endpoint public configuré, ou le listener SLB associé doit avoir l'ACL activé.",
		"pt": "Clusters ACK não devem ter um endpoint público configurado, ou o listener SLB associado deve ter ACL habilitado.",
	},
	"reason": {
		"en": "The ACK cluster has a public endpoint enabled, which may expose the API server to the internet.",
		"zh": "ACK 集群开启了公网连接端点，可能将 API Server 暴露给互联网。",
		"ja": "ACK クラスタでパブリックエンドポイントが有効になっているため、API サーバーがインターネットに公開される可能性があります。",
		"de": "Der ACK-Cluster hat einen öffentlichen Endpunkt aktiviert, was den API-Server dem Internet aussetzen kann.",
		"es": "El clúster ACK tiene un endpoint público habilitado, lo que puede exponer el servidor API a internet.",
		"fr": "Le cluster ACK a un endpoint public activé, ce qui peut exposer le serveur API à Internet.",
		"pt": "O cluster ACK tem um endpoint público habilitado, o que pode expor o servidor API à internet.",
	},
	"recommendation": {
		"en": "Disable the public endpoint for the ACK cluster by setting 'EndpointPublicAccess' to false.",
		"zh": "通过将'EndpointPublicAccess'设置为 false 来禁用 ACK 集群的公网连接端点。",
		"ja": "'EndpointPublicAccess' を false に設定して、ACK クラスタのパブリックエンドポイントを無効にします。",
		"de": "Deaktivieren Sie den öffentlichen Endpunkt für den ACK-Cluster, indem Sie 'EndpointPublicAccess' auf false setzen.",
		"es": "Deshabilite el endpoint público del clúster ACK estableciendo 'EndpointPublicAccess' en false.",
		"fr": "Désactivez l'endpoint public du cluster ACK en définissant 'EndpointPublicAccess' sur false.",
		"pt": "Desabilite o endpoint público do cluster ACK definindo 'EndpointPublicAccess' como false.",
	},
	"resource_types": [
		"ALIYUN::CS::ManagedKubernetesCluster",
		"ALIYUN::CS::ASKCluster",
	],
}

# Check for ManagedKubernetesCluster
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CS::ManagedKubernetesCluster")
	helpers.get_property(resource, "EndpointPublicAccess", false) == true
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EndpointPublicAccess"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

# Check for ASKCluster
# Default for ASKCluster EndpointPublicAccess is true
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CS::ASKCluster")
	is_ask_public_access_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EndpointPublicAccess"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

is_ask_public_access_enabled(resource) if {
	# If explicitly true
	helpers.get_property(resource, "EndpointPublicAccess", false) == true
}

is_ask_public_access_enabled(resource) if {
	# If missing, default is true
	not helpers.has_property(resource, "EndpointPublicAccess")
}
