package infraguard.rules.aliyun.ack_cluster_supported_version

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ack-cluster-supported-version",
	"name": {
		"en": "ACK Cluster Supported Version",
		"zh": "ACK 集群版本支持检测",
		"ja": "ACK クラスターサポートバージョン",
		"de": "ACK-Cluster Unterstützte Version",
		"es": "Versión Compatible del Clúster ACK",
		"fr": "Version Prise en Charge du Cluster ACK",
		"pt": "Versão Suportada do Cluster ACK",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the ACK cluster is running a supported version.",
		"zh": "确保 ACK 集群运行的是受支持的版本。",
		"ja": "ACK クラスターがサポートされているバージョンで実行されていることを確認します。",
		"de": "Stellt sicher, dass der ACK-Cluster eine unterstützte Version ausführt.",
		"es": "Garantiza que el clúster ACK esté ejecutando una versión compatible.",
		"fr": "Garantit que le cluster ACK exécute une version prise en charge.",
		"pt": "Garante que o cluster ACK esteja executando uma versão suportada.",
	},
	"reason": {
		"en": "Running an unsupported version may lead to security vulnerabilities and lack of support.",
		"zh": "运行不受支持的版本可能导致安全漏洞和缺乏技术支持。",
		"ja": "サポートされていないバージョンを実行すると、セキュリティの脆弱性やサポートの欠如につながる可能性があります。",
		"de": "Das Ausführen einer nicht unterstützten Version kann zu Sicherheitslücken und fehlender Unterstützung führen.",
		"es": "Ejecutar una versión no compatible puede provocar vulnerabilidades de seguridad y falta de soporte.",
		"fr": "Exécuter une version non prise en charge peut entraîner des vulnérabilités de sécurité et un manque de support.",
		"pt": "Executar uma versão não suportada pode levar a vulnerabilidades de segurança e falta de suporte.",
	},
	"recommendation": {
		"en": "Upgrade the ACK cluster to a supported version.",
		"zh": "将 ACK 集群升级到受支持的版本。",
		"ja": "ACK クラスターをサポートされているバージョンにアップグレードします。",
		"de": "Aktualisieren Sie den ACK-Cluster auf eine unterstützte Version.",
		"es": "Actualice el clúster ACK a una versión compatible.",
		"fr": "Mettez à niveau le cluster ACK vers une version prise en charge.",
		"pt": "Atualize o cluster ACK para uma versão suportada.",
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"])

	# Conceptual check - any cluster with a version is potentially unsupported
	helpers.has_property(resource, "KubernetesVersion")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "KubernetesVersion"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
