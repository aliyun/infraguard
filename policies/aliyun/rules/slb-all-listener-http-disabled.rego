package infraguard.rules.aliyun.slb_all_listener_http_disabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listener-http-disabled",
	"severity": "medium",
	"name": {
		"en": "SLB All Listeners HTTP Disabled",
		"zh": "SLB 禁用 HTTP 监听",
		"ja": "SLB すべてのリスナー HTTP が無効",
		"de": "SLB Alle Listener HTTP deaktiviert",
		"es": "HTTP de Todos los Oyentes SLB Deshabilitado",
		"fr": "HTTP de Tous les Écouteurs SLB Désactivé",
		"pt": "HTTP de Todos os Ouvintes SLB Desabilitado"
	},
	"description": {
		"en": "Ensures no SLB listeners use the insecure HTTP protocol.",
		"zh": "确保没有 SLB 监听使用不安全的 HTTP 协议。",
		"ja": "SLB リスナーが安全でない HTTP プロトコルを使用していないことを確認します。",
		"de": "Stellt sicher, dass keine SLB-Listener das unsichere HTTP-Protokoll verwenden.",
		"es": "Garantiza que ningún oyente SLB use el protocolo HTTP inseguro.",
		"fr": "Garantit qu'aucun écouteur SLB n'utilise le protocole HTTP non sécurisé.",
		"pt": "Garante que nenhum ouvinte SLB use o protocolo HTTP inseguro."
	},
	"reason": {
		"en": "HTTP traffic is unencrypted and vulnerable to interception.",
		"zh": "HTTP 流量未加密，容易被截获。",
		"ja": "HTTP トラフィックは暗号化されておらず、傍受されやすいです。",
		"de": "HTTP-Datenverkehr ist unverschlüsselt und anfällig für Abfangen.",
		"es": "El tráfico HTTP no está cifrado y es vulnerable a la interceptación.",
		"fr": "Le trafic HTTP n'est pas chiffré et vulnérable à l'interception.",
		"pt": "O tráfego HTTP não está criptografado e é vulnerável à interceptação."
	},
	"recommendation": {
		"en": "Disable HTTP listeners and use HTTPS instead.",
		"zh": "禁用 HTTP 监听并改用 HTTPS。",
		"ja": "HTTP リスナーを無効にし、代わりに HTTPS を使用します。",
		"de": "Deaktivieren Sie HTTP-Listener und verwenden Sie stattdessen HTTPS.",
		"es": "Deshabilite los oyentes HTTP y use HTTPS en su lugar.",
		"fr": "Désactivez les écouteurs HTTP et utilisez HTTPS à la place.",
		"pt": "Desabilite os ouvintes HTTP e use HTTPS em vez disso."
	},
	"resource_types": ["ALIYUN::SLB::Listener"]
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol != "http"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Protocol"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
