package infraguard.rules.terraform.polardb_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

# Rule metadata
rule_meta := {
	"id": "polardb-public-and-any-ip-access-check",
	"severity": "high",
	"name": {
		"en": "PolarDB Public and Any IP Access Check",
		"zh": "PolarDB 公网及全网 IP 访问检测",
		"ja": "PolarDB のパブリックおよび任意の IP アクセスチェック",
		"de": "PolarDB öffentlicher und beliebiger IP-Zugriff-Prüfung",
		"es": "Verificación de Acceso Público y de Cualquier IP de PolarDB",
		"fr": "Vérification d'Accès Public et de N'importe Quelle IP PolarDB",
		"pt": "Verificação de Acesso Público e de Qualquer IP do PolarDB"
	},
	"description": {
		"en": "Ensures that PolarDB clusters do not have security_ips open to any IP address (0.0.0.0/0 or 0.0.0.0).",
		"zh": "确保 PolarDB 集群的 security_ips 未对任何 IP 地址（0.0.0.0/0 或 0.0.0.0）开放。",
		"ja": "PolarDB クラスタの security_ips が任意の IP アドレス（0.0.0.0/0 または 0.0.0.0）に開放されていないことを確認します。",
		"de": "Stellt sicher, dass PolarDB-Cluster security_ips nicht für beliebige IP-Adressen (0.0.0.0/0 oder 0.0.0.0) geöffnet sind.",
		"es": "Garantiza que los clústeres PolarDB no tengan security_ips abiertos a ninguna dirección IP (0.0.0.0/0 o 0.0.0.0).",
		"fr": "Garantit que les clusters PolarDB n'ont pas security_ips ouverts à n'importe quelle adresse IP (0.0.0.0/0 ou 0.0.0.0).",
		"pt": "Garante que os clusters PolarDB não tenham security_ips abertos a qualquer endereço IP (0.0.0.0/0 ou 0.0.0.0)."
	},
	"reason": {
		"en": "Exposing a database to any IP address is a significant security risk.",
		"zh": "将数据库暴露给任何 IP 地址是重大的安全风险。",
		"ja": "データベースを任意の IP アドレスに公開することは、重大なセキュリティリスクです。",
		"de": "Das Freigeben einer Datenbank für beliebige IP-Adressen ist ein erhebliches Sicherheitsrisiko.",
		"es": "Exponer una base de datos a cualquier dirección IP es un riesgo de seguridad significativo.",
		"fr": "Exposer une base de données à n'importe quelle adresse IP est un risque de sécurité important.",
		"pt": "Expor um banco de dados a qualquer endereço IP é um risco de segurança significativo."
	},
	"recommendation": {
		"en": "Remove 0.0.0.0/0 and 0.0.0.0 from security_ips and restrict to specific trusted IP addresses.",
		"zh": "从 security_ips 中移除 0.0.0.0/0 和 0.0.0.0，并限制为特定的可信 IP 地址。",
		"ja": "security_ips から 0.0.0.0/0 と 0.0.0.0 を削除し、特定の信頼できる IP アドレスに制限します。",
		"de": "Entfernen Sie 0.0.0.0/0 und 0.0.0.0 aus security_ips und beschränken Sie auf spezifische vertrauenswürdige IP-Adressen.",
		"es": "Elimine 0.0.0.0/0 y 0.0.0.0 de security_ips y restrinja a direcciones IP confiables específicas.",
		"fr": "Supprimez 0.0.0.0/0 et 0.0.0.0 de security_ips et restreignez à des adresses IP de confiance spécifiques.",
		"pt": "Remova 0.0.0.0/0 e 0.0.0.0 de security_ips e restrinja a endereços IP confiáveis específicos."
	},
	"resource_types": ["alicloud_polardb_cluster"],
	"iac_type": "terraform"
}

has_any_ip_access(resource) if {
	security_ips := tf.get_attribute(resource, "security_ips", [])
	some ip in security_ips
	ip == "0.0.0.0/0"
}

has_any_ip_access(resource) if {
	security_ips := tf.get_attribute(resource, "security_ips", [])
	some ip in security_ips
	ip == "0.0.0.0"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_polardb_cluster")
	has_any_ip_access(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_polardb_cluster.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
