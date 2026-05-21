package infraguard.rules.terraform.slb_backendserver_weight_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-backendserver-weight-check",
	"severity": "low",
	"name": {
		"en": "SLB Backend Server Weight Check",
		"zh": "SLB 后端服务器权重配置核查",
		"ja": "SLB バックエンドサーバーの重みチェック",
		"de": "SLB-Backend-Server-Gewichtsprüfung",
		"es": "Verificación de Peso del Servidor Backend SLB",
		"fr": "Vérification du Poids du Serveur Backend SLB",
		"pt": "Verificação de Peso do Servidor Backend SLB"
	},
	"description": {
		"en": "Ensures SLB backend servers have at least one server with weight greater than 0.",
		"zh": "确保 SLB 后端服务器至少有一台权重大于 0 的服务器。",
		"ja": "SLB バックエンドサーバーに少なくとも 1 つの重みが 0 より大きいサーバーがあることを確認します。",
		"de": "Stellt sicher, dass SLB-Backend-Server mindestens einen Server mit Gewicht größer als 0 haben.",
		"es": "Garantiza que los servidores backend SLB tengan al menos un servidor con peso mayor a 0.",
		"fr": "Garantit que les serveurs backend SLB ont au moins un serveur avec un poids supérieur à 0.",
		"pt": "Garante que os servidores backend SLB tenham pelo menos um servidor com peso maior que 0."
	},
	"reason": {
		"en": "Uneven weight distribution can lead to unbalanced traffic and potential overload.",
		"zh": "权重分配不均可能导致流量失衡和潜在的负载过载。",
		"ja": "不均一な重み分布により、トラフィックの不均衡や潜在的な過負荷が発生する可能性があります。",
		"de": "Ungleichmäßige Gewichtsverteilung kann zu unausgewogenem Datenverkehr und potenzieller Überlastung führen.",
		"es": "La distribución desigual del peso puede provocar tráfico desequilibrado y sobrecarga potencial.",
		"fr": "Une distribution de poids inégale peut entraîner un trafic déséquilibré et une surcharge potentielle.",
		"pt": "A distribuição desigual de peso pode levar a tráfego desequilibrado e sobrecarga potencial."
	},
	"recommendation": {
		"en": "Ensure at least one backend_servers entry has weight greater than 0.",
		"zh": "确保至少一个 backend_servers 条目的权重大于 0。",
		"ja": "少なくとも 1 つの backend_servers エントリの重みが 0 より大きいことを確認します。",
		"de": "Stellen Sie sicher, dass mindestens ein backend_servers-Eintrag ein Gewicht größer als 0 hat.",
		"es": "Asegúrese de que al menos una entrada backend_servers tenga peso mayor a 0.",
		"fr": "Assurez-vous qu'au moins une entrée backend_servers a un poids supérieur à 0.",
		"pt": "Garanta que pelo menos uma entrada backend_servers tenha peso maior que 0."
	},
	"resource_types": ["alicloud_slb_backend_server"],
	"iac_type": "terraform"
}

as_array(value) := value if is_array(value)

else := [value] if is_object(value)

else := []

has_positive_weight(resource) if {
	servers := as_array(tf.get_attribute(resource, "backend_servers", []))
	some server in servers
	weight := object.get(server, "weight", 100)
	weight > 0
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_backend_server")
	not has_positive_weight(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_backend_server.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
