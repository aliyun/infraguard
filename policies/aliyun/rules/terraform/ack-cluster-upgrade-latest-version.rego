package infraguard.rules.terraform.ack_cluster_upgrade_latest_version

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ack-cluster-upgrade-latest-version",
	"severity": "medium",
	"name": {
		"en": "ACK Cluster Upgraded to Latest Version",
		"zh": "ACK 集群已升级至最新版本",
		"ja": "ACK クラスタが最新バージョンにアップグレードされている",
		"de": "ACK-Cluster auf neueste Version aktualisiert",
		"es": "Clúster ACK Actualizado a la Última Versión",
		"fr": "Cluster ACK Mis à Jour vers la Dernière Version",
		"pt": "Cluster ACK Atualizado para a Versão Mais Recente"
	},
	"description": {
		"en": "Ensures that the ACK cluster is running the latest available version.",
		"zh": "确保 ACK 集群运行的是最新的可用版本。",
		"ja": "ACK クラスタが最新の利用可能なバージョンを実行していることを確認します。",
		"de": "Stellt sicher, dass der ACK-Cluster die neueste verfügbare Version ausführt.",
		"es": "Garantiza que el clúster ACK esté ejecutando la última versión disponible.",
		"fr": "Garantit que le cluster ACK exécute la dernière version disponible.",
		"pt": "Garante que o cluster ACK esteja executando a versão mais recente disponível."
	},
	"reason": {
		"en": "Running the latest version ensures that you have the latest security patches and features.",
		"zh": "运行最新版本可确保您获得最新的安全补丁和功能。",
		"ja": "最新バージョンを実行することで、最新のセキュリティパッチと機能を確保できます。",
		"de": "Die Ausführung der neuesten Version stellt sicher, dass Sie die neuesten Sicherheitspatches und Funktionen haben.",
		"es": "Ejecutar la última versión garantiza que tenga los últimos parches de seguridad y funciones.",
		"fr": "L'exécution de la dernière version garantit que vous disposez des derniers correctifs de sécurité et fonctionnalités.",
		"pt": "Executar a versão mais recente garante que você tenha os patches de segurança e recursos mais recentes."
	},
	"recommendation": {
		"en": "Upgrade the ACK cluster to the latest available version.",
		"zh": "将 ACK 集群升级到最新的可用版本。",
		"ja": "ACK クラスタを最新の利用可能なバージョンにアップグレードします。",
		"de": "Aktualisieren Sie den ACK-Cluster auf die neueste verfügbare Version.",
		"es": "Actualice el clúster ACK a la última versión disponible.",
		"fr": "Mettez à jour le cluster ACK vers la dernière version disponible.",
		"pt": "Atualize o cluster ACK para a versão mais recente disponível."
	},
	"resource_types": ["alicloud_cs_managed_kubernetes"],
	"iac_type": "terraform"
}

latest_version_prefixes := ["1.35"]

is_latest_version(version) if {
	some prefix in latest_version_prefixes
	startswith(version, prefix)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_cs_managed_kubernetes")
	v := tf.get_attribute(resource, "version", "")
	not tf.is_unknown(v)
	v != ""
	not is_latest_version(v)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_cs_managed_kubernetes.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
