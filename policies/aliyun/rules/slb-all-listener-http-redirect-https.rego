package infraguard.rules.aliyun.slb_all_listener_http_redirect_https

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listener-http-redirect-https",
	"name": {
		"en": "SLB HTTP Redirect to HTTPS Enabled",
		"zh": "SLB 监听强制跳转 HTTPS",
		"ja": "SLB HTTP から HTTPS へのリダイレクトが有効",
		"de": "SLB HTTP-Weiterleitung zu HTTPS aktiviert",
		"es": "Redirección HTTP a HTTPS de SLB Habilitada",
		"fr": "Redirection HTTP vers HTTPS SLB Activée",
		"pt": "Redirecionamento HTTP para HTTPS do SLB Habilitado",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures SLB HTTP listeners are configured to redirect traffic to HTTPS.",
		"zh": "确保 SLB HTTP 监听已配置为将流量重定向至 HTTPS。",
		"ja": "SLB HTTP リスナーが HTTPS にトラフィックをリダイレクトするように設定されていることを確認します。",
		"de": "Stellt sicher, dass SLB-HTTP-Listener so konfiguriert sind, dass Datenverkehr zu HTTPS weitergeleitet wird.",
		"es": "Garantiza que los oyentes HTTP de SLB estén configurados para redirigir el tráfico a HTTPS.",
		"fr": "Garantit que les écouteurs HTTP SLB sont configurés pour rediriger le trafic vers HTTPS.",
		"pt": "Garante que os ouvintes HTTP do SLB estejam configurados para redirecionar o tráfego para HTTPS.",
	},
	"reason": {
		"en": "Redirecting HTTP to HTTPS ensures all client communication is encrypted.",
		"zh": "将 HTTP 重定向至 HTTPS 确保了所有客户端通信均经过加密。",
		"ja": "HTTP を HTTPS にリダイレクトすることで、すべてのクライアント通信が暗号化されます。",
		"de": "Die Weiterleitung von HTTP zu HTTPS stellt sicher, dass alle Client-Kommunikation verschlüsselt ist.",
		"es": "Redirigir HTTP a HTTPS garantiza que toda la comunicación del cliente esté cifrada.",
		"fr": "La redirection de HTTP vers HTTPS garantit que toute la communication client est chiffrée.",
		"pt": "Redirecionar HTTP para HTTPS garante que toda a comunicação do cliente esteja criptografada.",
	},
	"recommendation": {
		"en": "Enable HTTP-to-HTTPS redirection for the SLB listener.",
		"zh": "为 SLB 监听开启 HTTP 转 HTTPS 重定向。",
		"ja": "SLB リスナーの HTTP から HTTPS へのリダイレクトを有効にします。",
		"de": "Aktivieren Sie die HTTP-zu-HTTPS-Weiterleitung für den SLB-Listener.",
		"es": "Habilite la redirección HTTP a HTTPS para el oyente SLB.",
		"fr": "Activez la redirection HTTP vers HTTPS pour l'écouteur SLB.",
		"pt": "Habilite o redirecionamento HTTP para HTTPS para o ouvinte SLB.",
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol != "http"
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "http"

	# In ROS, check for HttpConfig.ListenerForward
	http_config := helpers.get_property(resource, "HttpConfig", {})
	is_object(http_config)
	http_config.ListenerForward == "on"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HttpConfig", "ListenerForward"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
