package infraguard.rules.terraform.hbase_cluster_in_vpc

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "hbase-cluster-in-vpc",
	"severity": "high",
	"name": {
		"en": "HBase Cluster Deployed in VPC",
		"zh": "HBase 集群部署在 VPC 中",
		"ja": "HBase クラスターが VPC にデプロイされている",
		"de": "HBase-Cluster in VPC bereitgestellt",
		"es": "Cluster HBase Implementado en VPC",
		"fr": "Cluster HBase Deploye dans un VPC",
		"pt": "Cluster HBase Implantado em VPC"
	},
	"description": {
		"en": "Ensures that HBase instances are deployed within a VPC.",
		"zh": "确保 HBase 实例部署在 VPC 中。",
		"ja": "HBase インスタンスが VPC 内にデプロイされていることを確認します。",
		"de": "Stellt sicher, dass HBase-Instanzen in einem VPC bereitgestellt werden.",
		"es": "Garantiza que las instancias HBase esten implementadas dentro de una VPC.",
		"fr": "Garantit que les instances HBase sont deployees dans un VPC.",
		"pt": "Garante que as instancias HBase estejam implantadas dentro de uma VPC."
	},
	"reason": {
		"en": "The HBase instance is not deployed within a VPC, which may expose it to security risks.",
		"zh": "HBase 实例未部署在 VPC 中，可能面临安全风险。",
		"ja": "HBase インスタンスが VPC 内にデプロイされておらず、セキュリティリスクにさらされる可能性があります。",
		"de": "Die HBase-Instanz ist nicht in einem VPC bereitgestellt, was sie Sicherheitsrisiken aussetzen kann.",
		"es": "La instancia HBase no esta implementada dentro de una VPC, lo que puede exponerla a riesgos de seguridad.",
		"fr": "L'instance HBase n'est pas deployee dans un VPC, ce qui peut l'exposer a des risques de securite.",
		"pt": "A instancia HBase nao esta implantada dentro de uma VPC, o que pode expola a riscos de seguranca."
	},
	"recommendation": {
		"en": "Deploy the HBase instance within a VPC by specifying the vpc_id attribute.",
		"zh": "通过指定 vpc_id 属性将 HBase 实例部署在 VPC 中。",
		"ja": "vpc_id 属性を指定して HBase インスタンスを VPC 内にデプロイします。",
		"de": "Stellen Sie die HBase-Instanz in einem VPC bereit, indem Sie das Attribut vpc_id angeben.",
		"es": "Implemente la instancia HBase dentro de una VPC especificando el atributo vpc_id.",
		"fr": "Deployez l'instance HBase dans un VPC en specifiant l'attribut vpc_id.",
		"pt": "Implante a instancia HBase dentro de uma VPC especificando o atributo vpc_id."
	},
	"resource_types": ["alicloud_hbase_instance"],
	"iac_type": "terraform"
}

is_in_vpc(resource) if {
	vpc_id := tf.get_attribute(resource, "vpc_id", "")
	not tf.is_unknown(vpc_id)
	vpc_id != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_hbase_instance")
	not is_in_vpc(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_hbase_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
