package infraguard.rules.aliyun.fc_function_custom_domain_and_tls_enable

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "fc-function-custom-domain-and-tls-enable",
	"severity": "medium",
	"name": {
		"en": "FC Function Custom Domain and TLS Enabled",
		"zh": "FC 函数自定义域名及 TLS 开启",
		"ja": "FC 関数カスタムドメインおよび TLS が有効",
		"de": "FC-Funktion Benutzerdefinierte Domain und TLS aktiviert",
		"es": "Dominio Personalizado y TLS de Función FC Habilitado",
		"fr": "Domaine Personnalisé et TLS de Fonction FC Activé",
		"pt": "Domínio Personalizado e TLS de Função FC Habilitado"
	},
	"description": {
		"en": "Ensures that custom domains for Function Compute functions have TLS enabled.",
		"zh": "确保函数计算函数的自定义域名已开启 TLS。",
		"ja": "関数計算関数のカスタムドメインで TLS が有効になっていることを確認します。",
		"de": "Stellt sicher, dass benutzerdefinierte Domains für Function Compute-Funktionen TLS aktiviert haben.",
		"es": "Garantiza que los dominios personalizados para funciones de Function Compute tengan TLS habilitado.",
		"fr": "Garantit que les domaines personnalisés pour les fonctions Function Compute ont TLS activé.",
		"pt": "Garante que os domínios personalizados para funções Function Compute tenham TLS habilitado."
	},
	"reason": {
		"en": "TLS encrypts traffic to your function, ensuring data confidentiality and integrity.",
		"zh": "TLS 对到函数的流量进行加密，确保数据机密性和完整性。",
		"ja": "TLS は関数へのトラフィックを暗号化し、データの機密性と整合性を確保します。",
		"de": "TLS verschlüsselt den Datenverkehr zu Ihrer Funktion und gewährleistet Datenvertraulichkeit und -integrität.",
		"es": "TLS cifra el tráfico a su función, garantizando la confidencialidad e integridad de los datos.",
		"fr": "TLS chiffre le trafic vers votre fonction, garantissant la confidentialité et l'intégrité des données.",
		"pt": "TLS criptografa o tráfego para sua função, garantindo confidencialidade e integridade dos dados."
	},
	"recommendation": {
		"en": "Configure an SSL certificate and enable TLS for the Function Compute custom domain.",
		"zh": "为函数计算自定义域名配置 SSL 证书并开启 TLS。",
		"ja": "SSL 証明書を設定し、関数計算カスタムドメインの TLS を有効にします。",
		"de": "Konfigurieren Sie ein SSL-Zertifikat und aktivieren Sie TLS für die Function Compute-Benutzerdomain.",
		"es": "Configure un certificado SSL y habilite TLS para el dominio personalizado de Function Compute.",
		"fr": "Configurez un certificat SSL et activez TLS pour le domaine personnalisé Function Compute.",
		"pt": "Configure um certificado SSL e habilite TLS para o domínio personalizado do Function Compute."
	},
	"resource_types": ["ALIYUN::FC::CustomDomain"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::CustomDomain")

	# Conceptual check for TLS
	not helpers.has_property(resource, "CertConfig")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
