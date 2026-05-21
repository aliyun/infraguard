package infraguard.rules.aliyun.ess_scaling_configuration_image_type_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ess-scaling-configuration-image-type-check",
	"severity": "medium",
	"name": {
		"en": "ESS Scaling Configuration Image Type Check",
		"zh": "弹性伸缩配置中使用指定来源的镜像",
		"ja": "ESS スケーリング設定イメージタイプチェック",
		"de": "ESS-Skalierungskonfiguration Bildtyp-Prüfung",
		"es": "Verificación de Tipo de Imagen de Configuración de Escalado ESS",
		"fr": "Vérification du Type d'Image de Configuration de Mise à l'Échelle ESS",
		"pt": "Verificação de Tipo de Imagem de Configuração de Escalonamento ESS"
	},
	"description": {
		"en": "ESS scaling configurations should use images from specified sources for better security and management.",
		"zh": "弹性伸缩配置中镜像来源为指定类型的来源，视为合规。参数默认值为共享类型。",
		"ja": "ESS スケーリング設定は、セキュリティと管理を向上させるために、指定されたソースからのイメージを使用する必要があります。",
		"de": "ESS-Skalierungskonfigurationen sollten Bilder aus angegebenen Quellen für bessere Sicherheit und Verwaltung verwenden.",
		"es": "Las configuraciones de escalado ESS deben usar imágenes de fuentes especificadas para mayor seguridad y gestión.",
		"fr": "Les configurations de mise à l'échelle ESS doivent utiliser des images provenant de sources spécifiées pour une meilleure sécurité et gestion.",
		"pt": "As configurações de escalonamento ESS devem usar imagens de fontes especificadas para melhor segurança e gerenciamento."
	},
	"reason": {
		"en": "The ESS scaling configuration is not using an image from the specified source type.",
		"zh": "弹性伸缩配置中镜像来源非指定类型，可能存在安全风险或管理问题。",
		"ja": "ESS スケーリング設定が指定されたソースタイプからのイメージを使用していません。",
		"de": "Die ESS-Skalierungskonfiguration verwendet kein Image vom angegebenen Quelltyp.",
		"es": "La configuración de escalado ESS no está usando una imagen del tipo de fuente especificado.",
		"fr": "La configuration de mise à l'échelle ESS n'utilise pas une image du type de source spécifié.",
		"pt": "A configuração de escalonamento ESS não está usando uma imagem do tipo de fonte especificado."
	},
	"recommendation": {
		"en": "Use images from trusted sources. Set the image source type according to your security requirements.",
		"zh": "使用来自可信来源的镜像。根据安全要求设置镜像来源类型。",
		"ja": "信頼できるソースからのイメージを使用します。セキュリティ要件に応じてイメージソースタイプを設定します。",
		"de": "Verwenden Sie Bilder aus vertrauenswürdigen Quellen. Legen Sie den Bildquelltyp gemäß Ihren Sicherheitsanforderungen fest.",
		"es": "Use imágenes de fuentes confiables. Establezca el tipo de fuente de imagen según sus requisitos de seguridad.",
		"fr": "Utilisez des images provenant de sources de confiance. Définissez le type de source d'image selon vos exigences de sécurité.",
		"pt": "Use imagens de fontes confiáveis. Defina o tipo de fonte da imagem de acordo com seus requisitos de segurança."
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"]
}

has_specified_image_type(resource) if {
	image_id := helpers.get_property(resource, "ImageId", "")
	image_id != ""
}

has_specified_image_type(resource) if {
	image_family := helpers.get_property(resource, "ImageFamily", "")
	image_family != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	not has_specified_image_type(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ImageId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
