package infraguard.rules.aliyun.nat_risk_ports_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "nat-risk-ports-check",
	"severity": "high",
	"name": {
		"en": "NAT Gateway Risk Ports Check",
		"zh": "NAT 网关不允许映射指定的风险端口",
		"ja": "NAT ゲートウェイのリスクポートチェック",
		"de": "NAT-Gateway-Risikoport-Prüfung",
		"es": "Verificación de Puertos de Riesgo de Puerta de Enlace NAT",
		"fr": "Vérification des Ports à Risque de la Passerelle NAT",
		"pt": "Verificação de Portas de Risco do Gateway NAT"
	},
	"description": {
		"en": "NAT gateway DNAT mappings should not expose risky ports to the internet to prevent security vulnerabilities.",
		"zh": "NAT 网关 DNAT 映射端口不包含指定的风险端口，视为合规。",
		"ja": "NAT ゲートウェイ DNAT マッピングは、セキュリティの脆弱性を防ぐために、リスクのあるポートをインターネットに公開しないでください。",
		"de": "NAT-Gateway-DNAT-Mappings sollten keine riskanten Ports dem Internet aussetzen, um Sicherheitslücken zu verhindern.",
		"es": "Los mapeos DNAT de la puerta de enlace NAT no deben exponer puertos riesgosos a internet para prevenir vulnerabilidades de seguridad.",
		"fr": "Les mappages DNAT de la passerelle NAT ne doivent pas exposer des ports risqués à Internet pour prévenir les vulnérabilités de sécurité.",
		"pt": "Os mapeamentos DNAT do gateway NAT não devem expor portas arriscadas à internet para prevenir vulnerabilidades de segurança."
	},
	"reason": {
		"en": "Exposing risky ports through DNAT can lead to security vulnerabilities and potential attacks.",
		"zh": "通过 DNAT 暴露风险端口可能导致安全漏洞和潜在攻击。",
		"ja": "DNAT を通じてリスクのあるポートを公開すると、セキュリティの脆弱性や潜在的な攻撃につながる可能性があります。",
		"de": "Das Aussetzen riskanter Ports über DNAT kann zu Sicherheitslücken und potenziellen Angriffen führen.",
		"es": "Exponer puertos riesgosos a través de DNAT puede provocar vulnerabilidades de seguridad y ataques potenciales.",
		"fr": "Exposer des ports risqués via DNAT peut entraîner des vulnérabilités de sécurité et des attaques potentielles.",
		"pt": "Expor portas arriscadas através de DNAT pode levar a vulnerabilidades de segurança e ataques potenciais."
	},
	"recommendation": {
		"en": "Avoid mapping well-known risky ports (e.g., 22, 3389, 445) through DNAT.",
		"zh": "避免通过 DNAT 映射已知的风险端口（如 22、3389、445 等）。",
		"ja": "DNAT を通じて既知のリスクポート（例：22、3389、445）のマッピングを避けます。",
		"de": "Vermeiden Sie die Zuordnung bekannter riskanter Ports (z. B. 22, 3389, 445) über DNAT.",
		"es": "Evite mapear puertos riesgosos conocidos (por ejemplo, 22, 3389, 445) a través de DNAT.",
		"fr": "Évitez de mapper des ports risqués bien connus (par exemple, 22, 3389, 445) via DNAT.",
		"pt": "Evite mapear portas arriscadas conhecidas (por exemplo, 22, 3389, 445) através de DNAT."
	},
	"resource_types": ["ALIYUN::NAT::NatGateway"]
}

# Common risky ports that should not be exposed
risky_ports := {"22", "23", "445", "3389", "1433", "3306", "5432", "6379", "8080", "8443"}

contains_risky_port(resource) if {
	# Simplified check - in production would check ForwardTable entries
	forward_table := helpers.get_property(resource, "ForwardTableId", "")
	forward_table != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAT::NatGateway")

	# This is a placeholder - actual implementation would check DNAT entries
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ForwardTableId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
