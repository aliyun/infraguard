package infraguard.rules.aliyun.security_center_version_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "security-center-version-check",
	"name": {
		"en": "Security Center Version Check",
		"zh": "云安全中心版本检测",
		"ja": "セキュリティセンターのバージョンチェック",
		"de": "Sicherheitszentrum Versionsprüfung",
		"es": "Verificación de Versión del Centro de Seguridad",
		"fr": "Vérification de Version du Centre de Sécurité",
		"pt": "Verificação de Versão do Centro de Segurança",
	},
	"severity": "medium",
	"description": {
		"en": "Security Center should be at a version that provides sufficient protection features.",
		"zh": "云安全中心版本满足要求，视为合规。",
		"ja": "セキュリティセンターは、十分な保護機能を提供するバージョンである必要があります。",
		"de": "Das Sicherheitszentrum sollte eine Version sein, die ausreichende Schutzfunktionen bietet.",
		"es": "El Centro de Seguridad debe estar en una versión que proporcione funciones de protección suficientes.",
		"fr": "Le Centre de Sécurité doit être à une version qui fournit des fonctionnalités de protection suffisantes.",
		"pt": "O Centro de Segurança deve estar em uma versão que forneça recursos de proteção suficientes.",
	},
	"reason": {
		"en": "A lower version of Security Center may not provide advanced threat detection and protection capabilities.",
		"zh": "较低版本的云安全中心可能无法提供先进的威胁检测和防御能力。",
		"ja": "セキュリティセンターの低いバージョンでは、高度な脅威検出と保護機能が提供されない可能性があります。",
		"de": "Eine niedrigere Version des Sicherheitszentrums bietet möglicherweise keine erweiterten Bedrohungserkennungs- und Schutzfunktionen.",
		"es": "Una versión inferior del Centro de Seguridad puede no proporcionar capacidades avanzadas de detección y protección de amenazas.",
		"fr": "Une version inférieure du Centre de Sécurité peut ne pas fournir de capacités avancées de détection et de protection contre les menaces.",
		"pt": "Uma versão inferior do Centro de Segurança pode não fornecer capacidades avançadas de detecção e proteção contra ameaças.",
	},
	"recommendation": {
		"en": "Upgrade Security Center to a higher version (e.g., Enterprise or Ultimate).",
		"zh": "将云安全中心升级到更高版本（如企业版或旗舰版）。",
		"ja": "セキュリティセンターをより高いバージョン（例：エンタープライズ版またはアルティメット版）にアップグレードします。",
		"de": "Aktualisieren Sie das Sicherheitszentrum auf eine höhere Version (z. B. Enterprise oder Ultimate).",
		"es": "Actualice el Centro de Seguridad a una versión superior (por ejemplo, Enterprise o Ultimate).",
		"fr": "Mettez à niveau le Centre de Sécurité vers une version supérieure (par exemple, Enterprise ou Ultimate).",
		"pt": "Atualize o Centro de Segurança para uma versão superior (por exemplo, Enterprise ou Ultimate).",
	},
	"resource_types": ["ALIYUN::ThreatDetection::Instance"],
}

# VersionCode values:
# level2: Enterprise Edition
# level3: Premium version
# level7: Antivirus Edition
# level8: Ultimate
# level10: Purchase value-added services only

is_compliant_version(resource) if {
	version := helpers.get_property(resource, "VersionCode", "")
	version == "level3" # Premium version
}

is_compliant_version(resource) if {
	version := helpers.get_property(resource, "VersionCode", "")
	version == "level8" # Ultimate
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant_version(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VersionCode"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
