package infraguard.rules.terraform.slb_listener_https_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-listener-https-enabled",
	"severity": "medium",
	"name": {
		"en": "SLB Listener HTTPS Enabled",
		"zh": "SLB 监听开启 HTTPS",
		"ja": "SLB リスナーで HTTPS が有効",
		"de": "SLB-Listener HTTPS aktiviert",
		"es": "HTTPS de Listener SLB Habilitado",
		"fr": "HTTPS du Listener SLB Activé",
		"pt": "HTTPS de Listener SLB Habilitado"
	},
	"description": {
		"en": "Ensures SLB listeners use HTTPS protocol for secure communication.",
		"zh": "确保 SLB 监听使用 HTTPS 协议以保障通信安全。",
		"ja": "SLB リスナーが安全な通信のために HTTPS プロトコルを使用することを確認します。",
		"de": "Stellt sicher, dass SLB-Listener das HTTPS-Protokoll für sichere Kommunikation verwenden.",
		"es": "Garantiza que los listeners SLB usen el protocolo HTTPS para comunicación segura.",
		"fr": "Garantit que les listeners SLB utilisent le protocole HTTPS pour une communication sécurisée.",
		"pt": "Garante que os listeners SLB usem o protocolo HTTPS para comunicação segura."
	},
	"reason": {
		"en": "HTTP protocol is insecure and prone to eavesdropping. HTTPS provides encryption.",
		"zh": "HTTP 协议不安全，容易被窃听。HTTPS 提供加密保障。",
		"ja": "HTTP プロトコルは安全ではなく、盗聴されやすいです。HTTPS は暗号化を提供します。",
		"de": "Das HTTP-Protokoll ist unsicher und anfällig für Abhören. HTTPS bietet Verschlüsselung.",
		"es": "El protocolo HTTP es inseguro y propenso a interceptación. HTTPS proporciona cifrado.",
		"fr": "Le protocole HTTP est non sécurisé et sujet à l'écoute. HTTPS fournit le chiffrement.",
		"pt": "O protocolo HTTP é inseguro e propenso a interceptação. HTTPS fornece criptografia."
	},
	"recommendation": {
		"en": "Set protocol to \"https\" in the alicloud_slb_listener resource.",
		"zh": "在 alicloud_slb_listener 资源中将 protocol 设置为 \"https\"。",
		"ja": "alicloud_slb_listener リソースで protocol を \"https\" に設定します。",
		"de": "Setzen Sie protocol auf \"https\" in der alicloud_slb_listener-Ressource.",
		"es": "Establezca protocol en \"https\" en el recurso alicloud_slb_listener.",
		"fr": "Définissez protocol sur \"https\" dans la ressource alicloud_slb_listener.",
		"pt": "Defina protocol como \"https\" no recurso alicloud_slb_listener."
	},
	"resource_types": ["alicloud_slb_listener"],
	"iac_type": "terraform"
}

is_https(resource) if {
	protocol := tf.get_attribute(resource, "protocol", "")
	not tf.is_unknown(protocol)
	protocol == "https"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_listener")
	not is_https(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_listener.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
