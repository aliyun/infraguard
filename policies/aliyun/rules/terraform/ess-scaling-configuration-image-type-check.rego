package infraguard.rules.terraform.ess_scaling_configuration_image_type_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "ESS scaling configurations should use images from specified sources.",
		"zh": "弹性伸缩配置中镜像来源为指定类型的来源，视为合规。",
		"ja": "ESS スケーリング設定は、セキュリティと管理を向上させるために、指定されたソースからのイメージを使用する必要があります。",
		"de": "ESS-Skalierungskonfigurationen sollten Bilder aus angegebenen Quellen für bessere Sicherheit und Verwaltung verwenden.",
		"es": "Las configuraciones de escalado ESS deben usar imágenes de fuentes especificadas para mayor seguridad y gestión.",
		"fr": "Les configurations de mise à l'échelle ESS doivent utiliser des images provenant de sources spécifiées pour une meilleure sécurité et gestion.",
		"pt": "As configurações de escalonamento ESS devem usar imagens de fontes especificadas para melhor segurança e gerenciamento."
	},
	"reason": {
		"en": "The ESS scaling configuration is not using a specified image source.",
		"zh": "弹性伸缩配置中镜像来源非指定类型，可能存在安全风险或管理问题。",
		"ja": "ESS スケーリング設定が指定されたソースタイプからのイメージを使用していません。",
		"de": "Die ESS-Skalierungskonfiguration verwendet kein Image vom angegebenen Quelltyp.",
		"es": "La configuración de escalado ESS no está usando una imagen del tipo de fuente especificado.",
		"fr": "La configuration de mise à l'échelle ESS n'utilise pas une image du type de source spécifié.",
		"pt": "A configuração de escalonamento ESS não está usando uma imagem do tipo de fonte especificado."
	},
	"recommendation": {
		"en": "Set image_id or image_name according to your trusted image source requirements.",
		"zh": "使用来自可信来源的镜像。",
		"ja": "信頼できるソースからのイメージを使用します。セキュリティ要件に応じてイメージソースタイプを設定します。",
		"de": "Verwenden Sie Bilder aus vertrauenswürdigen Quellen. Legen Sie den Bildquelltyp gemäß Ihren Sicherheitsanforderungen fest.",
		"es": "Use imágenes de fuentes confiables. Establezca el tipo de fuente de imagen según sus requisitos de seguridad.",
		"fr": "Utilisez des images provenant de sources de confiance. Définissez le type de source d'image selon vos exigences de sécurité.",
		"pt": "Use imagens de fontes confiáveis. Defina o tipo de fonte da imagem de acordo com seus requisitos de segurança."
	},
	"resource_types": ["alicloud_ess_scaling_configuration"],
	"iac_type": "terraform"
}

has_specified_image(resource) if {
	image_id := tf.get_attribute(resource, "image_id", "")
	not tf.is_unknown(image_id)
	image_id != ""
}

has_specified_image(resource) if {
	image_name := tf.get_attribute(resource, "image_name", "")
	not tf.is_unknown(image_name)
	image_name != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ess_scaling_configuration")
	not has_specified_image(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ess_scaling_configuration.%s", [name]),
		"violation_path": ["image_id"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
