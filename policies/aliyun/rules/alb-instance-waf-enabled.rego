package infraguard.rules.aliyun.alb_instance_waf_enabled

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "alb-instance-waf-enabled",
	"name": {
		"en": "ALB Instance Has WAF Protection",
		"zh": "ALB 实例开启 WEB 应用防火墙防护",
		"ja": "ALB インスタンスに WAF 保護がある",
		"de": "ALB-Instanz hat WAF-Schutz",
		"es": "La Instancia ALB Tiene Protección WAF",
		"fr": "L'Instance ALB a une Protection WAF",
		"pt": "A Instância ALB Tem Proteção WAF",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ALB instances have WAF3 (Web Application Firewall) protection enabled.",
		"zh": "确保 ALB 实例已启用 WAF3（Web 应用防火墙）防护。",
		"ja": "ALB インスタンスで WAF3（Web アプリケーションファイアウォール）保護が有効になっていることを確認します。",
		"de": "Stellt sicher, dass ALB-Instanzen WAF3 (Web Application Firewall) Schutz aktiviert haben.",
		"es": "Garantiza que las instancias ALB tengan protección WAF3 (Web Application Firewall) habilitada.",
		"fr": "Garantit que les instances ALB ont la protection WAF3 (Web Application Firewall) activée.",
		"pt": "Garante que as instâncias ALB tenham proteção WAF3 (Web Application Firewall) habilitada.",
	},
	"reason": {
		"en": "WAF protection helps protect against common web vulnerabilities and attacks.",
		"zh": "WAF 防护有助于防范常见的 Web 漏洞和攻击。",
		"ja": "WAF 保護は、一般的な Web の脆弱性や攻撃から保護するのに役立ちます。",
		"de": "WAF-Schutz hilft, vor häufigen Web-Schwachstellen und Angriffen zu schützen.",
		"es": "La protección WAF ayuda a protegerse contra vulnerabilidades y ataques web comunes.",
		"fr": "La protection WAF aide à se protéger contre les vulnérabilités et attaques Web courantes.",
		"pt": "A proteção WAF ajuda a proteger contra vulnerabilidades e ataques web comuns.",
	},
	"recommendation": {
		"en": "Enable WAF3 protection for the ALB instance.",
		"zh": "为 ALB 实例启用 WAF3 防护。",
		"ja": "ALB インスタンスの WAF3 保護を有効にします。",
		"de": "Aktivieren Sie WAF3-Schutz für die ALB-Instanz.",
		"es": "Habilite la protección WAF3 para la instancia ALB.",
		"fr": "Activez la protection WAF3 pour l'instance ALB.",
		"pt": "Habilite a proteção WAF3 para a instância ALB.",
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"],
}

# Check if WAF protection is enabled via LoadBalancerEdition
is_compliant(resource) if {
	edition := helpers.get_property(resource, "LoadBalancerEdition", "")
	edition == "StandardWithWaf"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "WafEnabled"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
