package infraguard.rules.terraform.slb_all_listenter_tls_policy_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-all-listenter-tls-policy-check",
	"severity": "medium",
	"name": {
		"en": "SLB Listener TLS Policy Check",
		"zh": "SLB 监听使用安全 TLS 策略",
		"ja": "SLB リスナーの TLS ポリシーチェック",
		"de": "SLB Listener TLS-Richtlinien-Prüfung",
		"es": "Verificación de Política TLS del Listener SLB",
		"fr": "Vérification de la Politique TLS du Listener SLB",
		"pt": "Verificação de Política TLS do Listener SLB"
	},
	"description": {
		"en": "Ensures SLB HTTPS listeners use secure TLS cipher policies.",
		"zh": "确保 SLB HTTPS 监听使用安全的 TLS 加密策略。",
		"ja": "SLB HTTPS リスナーが安全な TLS 暗号化ポリシーを使用していることを確認します。",
		"de": "Stellt sicher, dass SLB HTTPS-Listener sichere TLS-Verschlüsselungsrichtlinien verwenden.",
		"es": "Garantiza que los listeners HTTPS de SLB usen políticas de cifrado TLS seguras.",
		"fr": "Garantit que les listeners HTTPS SLB utilisent des politiques de chiffrement TLS sécurisées.",
		"pt": "Garante que os listeners HTTPS SLB usem políticas de criptografia TLS seguras."
	},
	"reason": {
		"en": "Weak cipher suites can be exploited to decrypt intercepted traffic.",
		"zh": "弱加密套件可能被利用来解密截获的流量。",
		"ja": "弱い暗号スイートは、傍受されたトラフィックを復号化するために悪用される可能性があります。",
		"de": "Schwache Verschlüsselungssuiten können ausgenutzt werden, um abgefangenen Datenverkehr zu entschlüsseln.",
		"es": "Las suites de cifrado débiles pueden ser explotadas para descifrar el tráfico interceptado.",
		"fr": "Les suites de chiffrement faibles peuvent être exploitées pour déchiffrer le trafic intercepté.",
		"pt": "Suites de criptografia fracas podem ser exploradas para descriptografar tráfego interceptado."
	},
	"recommendation": {
		"en": "Set tls_cipher_policy to 'tls_cipher_policy_1_2' or higher for HTTPS listeners.",
		"zh": "为 HTTPS 监听将 tls_cipher_policy 设置为 'tls_cipher_policy_1_2' 或更高版本。",
		"ja": "HTTPS リスナーの tls_cipher_policy を 'tls_cipher_policy_1_2' 以上に設定します。",
		"de": "Setzen Sie tls_cipher_policy für HTTPS-Listener auf 'tls_cipher_policy_1_2' oder höher.",
		"es": "Establezca tls_cipher_policy en 'tls_cipher_policy_1_2' o superior para listeners HTTPS.",
		"fr": "Définissez tls_cipher_policy sur 'tls_cipher_policy_1_2' ou supérieur pour les listeners HTTPS.",
		"pt": "Defina tls_cipher_policy como 'tls_cipher_policy_1_2' ou superior para listeners HTTPS."
	},
	"resource_types": ["alicloud_slb_listener"],
	"iac_type": "terraform"
}

# Non-HTTPS listeners are compliant
is_compliant(resource) if {
	tf.get_attribute(resource, "protocol", "") != "https"
}

# HTTPS listeners with secure TLS policy are compliant
is_compliant(resource) if {
	tf.get_attribute(resource, "protocol", "") == "https"
	policy := tf.get_attribute(resource, "tls_cipher_policy", "")
	policy != ""
	not policy in {"tls_cipher_policy_1_0", "tls_cipher_policy_1_1"}
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
