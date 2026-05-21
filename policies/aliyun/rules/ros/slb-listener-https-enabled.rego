package infraguard.rules.aliyun.slb_listener_https_enabled

import data.infraguard.helpers
import rego.v1

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
		"en": "Configure SLB listeners to use HTTPS instead of HTTP.",
		"zh": "将 SLB 监听配置为使用 HTTPS 而非 HTTP。",
		"ja": "SLB リスナーを HTTP ではなく HTTPS を使用するように設定します。",
		"de": "Konfigurieren Sie SLB-Listener so, dass sie HTTPS anstelle von HTTP verwenden.",
		"es": "Configure listeners SLB para usar HTTPS en lugar de HTTP.",
		"fr": "Configurez les listeners SLB pour utiliser HTTPS au lieu de HTTP.",
		"pt": "Configure listeners SLB para usar HTTPS em vez de HTTP."
	},
	"resource_types": ["ALIYUN::SLB::Listener"]
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "https"
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
