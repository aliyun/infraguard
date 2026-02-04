package infraguard.rules.aliyun.slb_all_listenter_tls_policy_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listenter-tls-policy-check",
	"name": {
		"en": "SLB Listener TLS Policy Check",
		"zh": "SLB 监听使用安全 TLS 策略",
		"ja": "SLB リスナーの TLS ポリシーチェック",
		"de": "SLB Listener TLS-Richtlinien-Prüfung",
		"es": "Verificación de Política TLS del Listener SLB",
		"fr": "Vérification de la Politique TLS du Listener SLB",
		"pt": "Verificação de Política TLS do Listener SLB",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures SLB HTTPS listeners use secure TLS cipher policies.",
		"zh": "确保 SLB HTTPS 监听使用安全的 TLS 加密策略。",
		"ja": "SLB HTTPS リスナーが安全な TLS 暗号化ポリシーを使用していることを確認します。",
		"de": "Stellt sicher, dass SLB HTTPS-Listener sichere TLS-Verschlüsselungsrichtlinien verwenden.",
		"es": "Garantiza que los listeners HTTPS de SLB usen políticas de cifrado TLS seguras.",
		"fr": "Garantit que les listeners HTTPS SLB utilisent des politiques de chiffrement TLS sécurisées.",
		"pt": "Garante que os listeners HTTPS SLB usem políticas de criptografia TLS seguras.",
	},
	"reason": {
		"en": "Weak cipher suites can be exploited to decrypt intercepted traffic.",
		"zh": "弱加密套件可能被利用来解密截获的流量。",
		"ja": "弱い暗号スイートは、傍受されたトラフィックを復号化するために悪用される可能性があります。",
		"de": "Schwache Verschlüsselungssuiten können ausgenutzt werden, um abgefangenen Datenverkehr zu entschlüsseln.",
		"es": "Las suites de cifrado débiles pueden ser explotadas para descifrar el tráfico interceptado.",
		"fr": "Les suites de chiffrement faibles peuvent être exploitées pour déchiffrer le trafic intercepté.",
		"pt": "Suites de criptografia fracas podem ser exploradas para descriptografar tráfego interceptado.",
	},
	"recommendation": {
		"en": "Use a recommended TLS policy like 'tls_cipher_policy_1_2'.",
		"zh": "使用推荐的 TLS 策略，如 'tls_cipher_policy_1_2'。",
		"ja": "'tls_cipher_policy_1_2' などの推奨 TLS ポリシーを使用します。",
		"de": "Verwenden Sie eine empfohlene TLS-Richtlinie wie 'tls_cipher_policy_1_2'.",
		"es": "Use una política TLS recomendada como 'tls_cipher_policy_1_2'.",
		"fr": "Utilisez une politique TLS recommandée comme 'tls_cipher_policy_1_2'.",
		"pt": "Use uma política TLS recomendada como 'tls_cipher_policy_1_2'.",
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol != "https"
}

is_compliant(resource) if {
	protocol := helpers.get_property(resource, "Protocol", "")
	protocol == "https"
	policy := helpers.get_property(resource, "TLSCipherPolicy", "")

	# Example: must be 1.2 or higher
	policy != ""
	not helpers.includes(["tls_cipher_policy_1_0", "tls_cipher_policy_1_1"], policy)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TLSCipherPolicy"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
