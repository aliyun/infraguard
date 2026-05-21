package infraguard.rules.terraform.slb_all_listener_http_disabled

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Set protocol to 'https' or 'tcp' instead of 'http'.",
		"zh": "将 protocol 设置为 'https' 或 'tcp'，而非 'http'。",
		"ja": "protocol を 'http' ではなく 'https' または 'tcp' に設定します。",
		"de": "Setzen Sie protocol auf 'https' oder 'tcp' statt 'http'.",
		"es": "Establezca protocol en 'https' o 'tcp' en lugar de 'http'.",
		"fr": "Définissez protocol sur 'https' ou 'tcp' au lieu de 'http'.",
		"pt": "Defina protocol como 'https' ou 'tcp' em vez de 'http'."
	},
	"resource_types": ["alicloud_slb_listener"],
	"iac_type": "terraform"
}

is_http_protocol(resource) if {
	tf.get_attribute(resource, "protocol", "") == "http"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_listener")
	is_http_protocol(resource)
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
