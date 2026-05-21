package infraguard.rules.terraform.slb_all_listener_http_redirect_https

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-all-listener-http-redirect-https",
	"severity": "medium",
	"name": {
		"en": "SLB HTTP Redirect to HTTPS Enabled",
		"zh": "SLB 监听强制跳转 HTTPS",
		"ja": "SLB HTTP から HTTPS へのリダイレクトが有効",
		"de": "SLB HTTP-Weiterleitung zu HTTPS aktiviert",
		"es": "Redirección HTTP a HTTPS de SLB Habilitada",
		"fr": "Redirection HTTP vers HTTPS SLB Activée",
		"pt": "Redirecionamento HTTP para HTTPS do SLB Habilitado"
	},
	"description": {
		"en": "Ensures SLB HTTP listeners are configured to redirect traffic to HTTPS.",
		"zh": "确保 SLB HTTP 监听已配置为将流量重定向至 HTTPS。",
		"ja": "SLB HTTP リスナーが HTTPS にトラフィックをリダイレクトするように設定されていることを確認します。",
		"de": "Stellt sicher, dass SLB-HTTP-Listener so konfiguriert sind, dass Datenverkehr zu HTTPS weitergeleitet wird.",
		"es": "Garantiza que los oyentes HTTP de SLB estén configurados para redirigir el tráfico a HTTPS.",
		"fr": "Garantit que les écouteurs HTTP SLB sont configurés pour rediriger le trafic vers HTTPS.",
		"pt": "Garante que os ouvintes HTTP do SLB estejam configurados para redirecionar o tráfego para HTTPS."
	},
	"reason": {
		"en": "Redirecting HTTP to HTTPS ensures all client communication is encrypted.",
		"zh": "将 HTTP 重定向至 HTTPS 确保了所有客户端通信均经过加密。",
		"ja": "HTTP を HTTPS にリダイレクトすることで、すべてのクライアント通信が暗号化されます。",
		"de": "Die Weiterleitung von HTTP zu HTTPS stellt sicher, dass alle Client-Kommunikation verschlüsselt ist.",
		"es": "Redirigir HTTP a HTTPS garantiza que toda la comunicación del cliente esté cifrada.",
		"fr": "La redirection de HTTP vers HTTPS garantit que toute la communication client est chiffrée.",
		"pt": "Redirecionar HTTP para HTTPS garante que toda a comunicação do cliente esteja criptografada."
	},
	"recommendation": {
		"en": "Set listener_forward to 'on' for HTTP listeners to redirect to HTTPS.",
		"zh": "为 HTTP 监听将 listener_forward 设置为 'on' 以重定向至 HTTPS。",
		"ja": "HTTP リスナーの listener_forward を 'on' に設定して HTTPS にリダイレクトします。",
		"de": "Setzen Sie listener_forward für HTTP-Listener auf 'on', um zu HTTPS weiterzuleiten.",
		"es": "Establezca listener_forward en 'on' para los oyentes HTTP para redirigir a HTTPS.",
		"fr": "Définissez listener_forward sur 'on' pour les écouteurs HTTP pour rediriger vers HTTPS.",
		"pt": "Defina listener_forward como 'on' para ouvintes HTTP para redirecionar para HTTPS."
	},
	"resource_types": ["alicloud_slb_listener"],
	"iac_type": "terraform"
}

# Non-HTTP listeners are compliant
is_compliant(resource) if {
	tf.get_attribute(resource, "protocol", "") != "http"
}

# HTTP listeners with forward enabled are compliant
is_compliant(resource) if {
	tf.get_attribute(resource, "protocol", "") == "http"
	tf.get_attribute(resource, "listener_forward", "off") == "on"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_listener")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_listener.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
