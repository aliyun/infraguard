package infraguard.rules.terraform.ack_cluster_inspect_kubelet_version_outdate_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ack-cluster-inspect-kubelet-version-outdate-check",
	"severity": "medium",
	"name": {
		"en": "ACK Kubelet Version Check",
		"zh": "ACK 巡检：Kubelet 版本过时检测",
		"ja": "ACK Kubelet バージョンチェック",
		"de": "ACK Kubelet Versionsprüfung",
		"es": "Verificación de Versión de Kubelet ACK",
		"fr": "Vérification de Version Kubelet ACK",
		"pt": "Verificação de Versão do Kubelet ACK"
	},
	"description": {
		"en": "Ensures the Kubelet version in the ACK cluster is up to date.",
		"zh": "确保 ACK 集群中的 Kubelet 版本是最新的。",
		"ja": "ACK クラスタ内の Kubelet バージョンが最新であることを確認します。",
		"de": "Stellt sicher, dass die Kubelet-Version im ACK-Cluster auf dem neuesten Stand ist.",
		"es": "Garantiza que la versión de Kubelet en el clúster ACK esté actualizada.",
		"fr": "Garantit que la version Kubelet dans le cluster ACK est à jour.",
		"pt": "Garante que a versão do Kubelet no cluster ACK esteja atualizada."
	},
	"reason": {
		"en": "Outdated Kubelet versions may contain security vulnerabilities or compatibility issues.",
		"zh": "过时的 Kubelet 版本可能包含安全漏洞或兼容性问题。",
		"ja": "古い Kubelet バージョンには、セキュリティの脆弱性や互換性の問題が含まれている可能性があります。",
		"de": "Veraltete Kubelet-Versionen können Sicherheitslücken oder Kompatibilitätsprobleme enthalten.",
		"es": "Las versiones obsoletas de Kubelet pueden contener vulnerabilidades de seguridad o problemas de compatibilidad.",
		"fr": "Les versions obsolètes de Kubelet peuvent contenir des vulnérabilités de sécurité ou des problèmes de compatibilité.",
		"pt": "Versões desatualizadas do Kubelet podem conter vulnerabilidades de segurança ou problemas de compatibilidade."
	},
	"recommendation": {
		"en": "Upgrade the Kubelet version of the worker nodes.",
		"zh": "升级工作节点的 Kubelet 版本。",
		"ja": "ワーカーノードの Kubelet バージョンをアップグレードします。",
		"de": "Aktualisieren Sie die Kubelet-Version der Worker-Knoten.",
		"es": "Actualice la versión de Kubelet de los nodos trabajadores.",
		"fr": "Mettez à niveau la version Kubelet des nœuds de travail.",
		"pt": "Atualize a versão do Kubelet dos nós de trabalho."
	},
	"resource_types": ["alicloud_cs_managed_kubernetes"],
	"iac_type": "terraform"
}

# Outdated versions that are flagged
outdated_versions := ["1.16", "1.18"]

# Check if version is compliant (not outdated)
is_compliant(resource) if {
	v := tf.get_attribute(resource, "version", "")
	not tf.is_unknown(v)
	not v in outdated_versions
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_cs_managed_kubernetes")
	not is_compliant(resource)
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
