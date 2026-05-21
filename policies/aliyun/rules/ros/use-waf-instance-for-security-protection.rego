package infraguard.rules.aliyun.use_waf_instance_for_security_protection

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "use-waf-instance-for-security-protection",
	"severity": "high",
	"name": {
		"en": "Use WAF for Security Protection",
		"zh": "使用 WEB 防火墙对网站或 APP 进行安全防护",
		"ja": "セキュリティ保護に WAF を使用",
		"de": "Verwenden Sie WAF für Sicherheitsschutz",
		"es": "Usar WAF para Protección de Seguridad",
		"fr": "Utiliser WAF pour la Protection de Sécurité",
		"pt": "Usar WAF para Proteção de Segurança"
	},
	"description": {
		"en": "WEB Application Firewall (WAF) should be used to protect websites and APPs from web-based attacks.",
		"zh": "使用 WEB 防火墙对网站或 APP 进行安全防护，视为合规。",
		"ja": "Web アプリケーションファイアウォール（WAF）を使用して、Web サイトとアプリを Web ベースの攻撃から保護する必要があります。",
		"de": "Web Application Firewall (WAF) sollte verwendet werden, um Websites und Apps vor webbasierten Angriffen zu schützen.",
		"es": "El Firewall de Aplicaciones Web (WAF) debe usarse para proteger sitios web y aplicaciones de ataques basados en web.",
		"fr": "Le Pare-feu d'Application Web (WAF) doit être utilisé pour protéger les sites web et les applications contre les attaques basées sur le web.",
		"pt": "O Firewall de Aplicações Web (WAF) deve ser usado para proteger sites e aplicativos de ataques baseados na web."
	},
	"reason": {
		"en": "The ALB instance does not have WAF enabled, leaving web assets vulnerable to attacks.",
		"zh": "ALB 实例未启用 WAF 防护，使 Web 资产容易受到攻击。",
		"ja": "ALB インスタンスで WAF が有効になっていないため、Web アセットが攻撃に対して脆弱になります。",
		"de": "Die ALB-Instanz hat WAF nicht aktiviert, wodurch Web-Assets anfällig für Angriffe sind.",
		"es": "La instancia ALB no tiene WAF habilitado, dejando los activos web vulnerables a ataques.",
		"fr": "L'instance ALB n'a pas WAF activé, laissant les actifs web vulnérables aux attaques.",
		"pt": "A instância ALB não tem WAF habilitado, deixando os ativos web vulneráveis a ataques."
	},
	"recommendation": {
		"en": "Enable WAF for the ALB instance by setting LoadBalancerEdition to 'StandardWithWaf'.",
		"zh": "通过将 LoadBalancerEdition 设置为 'StandardWithWaf' 为 ALB 实例开启 WAF 防护。",
		"ja": "LoadBalancerEdition を 'StandardWithWaf' に設定して、ALB インスタンスの WAF を有効にします。",
		"de": "Aktivieren Sie WAF für die ALB-Instanz, indem Sie LoadBalancerEdition auf 'StandardWithWaf' setzen.",
		"es": "Habilite WAF para la instancia ALB estableciendo LoadBalancerEdition en 'StandardWithWaf'.",
		"fr": "Activez WAF pour l'instance ALB en définissant LoadBalancerEdition sur 'StandardWithWaf'.",
		"pt": "Habilite WAF para a instância ALB definindo LoadBalancerEdition como 'StandardWithWaf'."
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"]
}

# Check if ALB has WAF enabled via its edition
is_waf_enabled(resource) if {
	helpers.get_property(resource, "LoadBalancerEdition", "") == "StandardWithWaf"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_waf_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoadBalancerEdition"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
