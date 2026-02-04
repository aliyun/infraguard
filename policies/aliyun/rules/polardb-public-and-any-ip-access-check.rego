package infraguard.rules.aliyun.polardb_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers

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
		"en": "Ensures that PolarDB clusters do not have public endpoints and are not open to any IP address (0.0.0.0/0).",
		"zh": "确保 PolarDB 集群没有公网端点，并且未对任何 IP 地址(0.0.0.0/0)开放。",
		"ja": "PolarDB クラスタにパブリックエンドポイントがなく、任意の IP アドレス（0.0.0.0/0）に開放されていないことを確認します。",
		"de": "Stellt sicher, dass PolarDB-Cluster keine öffentlichen Endpunkte haben und nicht für beliebige IP-Adressen (0.0.0.0/0) geöffnet sind.",
		"es": "Garantiza que los clústeres PolarDB no tengan endpoints públicos y no estén abiertos a ninguna dirección IP (0.0.0.0/0).",
		"fr": "Garantit que les clusters PolarDB n'ont pas d'endpoints publics et ne sont pas ouverts à n'importe quelle adresse IP (0.0.0.0/0).",
		"pt": "Garante que os clusters PolarDB não tenham endpoints públicos e não estejam abertos a qualquer endereço IP (0.0.0.0/0)."
	},
	"reason": {
		"en": "Exposing a database to the public internet or any IP address is a significant security risk.",
		"zh": "将数据库暴露给公网或任何 IP 地址是重大的安全风险。",
		"ja": "データベースをパブリックインターネットまたは任意の IP アドレスに公開することは、重大なセキュリティリスクです。",
		"de": "Das Freigeben einer Datenbank für das öffentliche Internet oder beliebige IP-Adressen ist ein erhebliches Sicherheitsrisiko.",
		"es": "Exponer una base de datos a internet público o cualquier dirección IP es un riesgo de seguridad significativo.",
		"fr": "Exposer une base de données à Internet public ou à n'importe quelle adresse IP est un risque de sécurité important.",
		"pt": "Expor um banco de dados à internet pública ou qualquer endereço IP é um risco de segurança significativo."
	},
	"recommendation": {
		"en": "Disable public endpoints for the PolarDB cluster and restrict the white list to specific IP addresses.",
		"zh": "为 PolarDB 集群禁用公网端点，并将白名单限制为特定的 IP 地址。",
		"ja": "PolarDB クラスタのパブリックエンドポイントを無効にし、ホワイトリストを特定の IP アドレスに制限します。",
		"de": "Deaktivieren Sie öffentliche Endpunkte für den PolarDB-Cluster und beschränken Sie die Whitelist auf spezifische IP-Adressen.",
		"es": "Deshabilite endpoints públicos para el clúster PolarDB y restrinja la lista blanca a direcciones IP específicas.",
		"fr": "Désactivez les endpoints publics pour le cluster PolarDB et restreignez la liste blanche à des adresses IP spécifiques.",
		"pt": "Desabilite endpoints públicos para o cluster PolarDB e restrinja a lista branca a endereços IP específicos."
	},
	"resource_types": ["ALIYUN::POLARDB::DBCluster"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")

	# Check if SecurityIPList contains 0.0.0.0/0 (any IP access)
	whitelist := helpers.get_property(resource, "SecurityIPList", "")
	whitelist == "0.0.0.0/0"
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPList"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::POLARDB::DBCluster")

	# Check if SecurityIPList contains 0.0.0.0/0 in comma-separated list
	whitelist := helpers.get_property(resource, "SecurityIPList", "")
	contains(whitelist, "0.0.0.0/0")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPList"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
