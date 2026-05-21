package infraguard.rules.terraform.ess_scaling_configuration_image_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ess-scaling-configuration-image-check",
	"severity": "medium",
	"name": {
		"en": "ESS Scaling Configuration Image Check",
		"zh": "弹性伸缩配置镜像检测",
		"ja": "ESS スケーリング設定イメージチェック",
		"de": "ESS-Skalierungskonfiguration Bildprüfung",
		"es": "Verificación de Imagen de Configuración de Escalado ESS",
		"fr": "Vérification d'Image de Configuration de Mise à l'Échelle ESS",
		"pt": "Verificação de Imagem da Configuração de Escalonamento ESS"
	},
	"description": {
		"en": "ESS scaling configurations should specify a maintained image.",
		"zh": "弹性伸缩配置中镜像为保有中资源，视为合规。",
		"ja": "ESS スケーリング設定は、セキュリティと安定性を確保するために、メンテナンスされたイメージを使用する必要があります。",
		"de": "ESS-Skalierungskonfigurationen sollten gewartete Images verwenden, um Sicherheit und Stabilität zu gewährleisten.",
		"es": "Las configuraciones de escalado ESS deben usar imágenes mantenidas para garantizar seguridad y estabilidad.",
		"fr": "Les configurations de mise à l'échelle ESS doivent utiliser des images maintenues pour assurer la sécurité et la stabilité.",
		"pt": "As configurações de escalonamento ESS devem usar imagens mantidas para garantir segurança e estabilidade."
	},
	"reason": {
		"en": "The ESS scaling configuration does not specify an image.",
		"zh": "弹性伸缩配置中使用的镜像可能已不再维护或不再可用。",
		"ja": "ESS スケーリング設定が、もはやメンテナンスされていないか、利用できないイメージを使用している可能性があります。",
		"de": "Die ESS-Skalierungskonfiguration verwendet möglicherweise ein Image, das nicht mehr gewartet oder verfügbar ist.",
		"es": "La configuración de escalado ESS puede estar usando una imagen que ya no se mantiene o está disponible.",
		"fr": "La configuration de mise à l'échelle ESS peut utiliser une image qui n'est plus maintenue ou disponible.",
		"pt": "A configuração de escalonamento ESS pode estar usando uma imagem que não é mais mantida ou disponível."
	},
	"recommendation": {
		"en": "Set image_id or image_name to a valid image.",
		"zh": "指定有效镜像。",
		"ja": "メンテナンス状態のイメージを使用します。ImageId または ImageFamily プロパティで有効なイメージ ID を指定できます。",
		"de": "Verwenden Sie Images, die sich im Wartungsstatus befinden. Sie können ImageId- oder ImageFamily-Eigenschaften mit gültigen Image-IDs verwenden.",
		"es": "Use imágenes que estén en estado mantenido. Puede usar las propiedades ImageId o ImageFamily con ID de imagen válidos.",
		"fr": "Utilisez des images qui sont en état maintenu. Vous pouvez utiliser les propriétés ImageId ou ImageFamily avec des ID d'image valides.",
		"pt": "Use imagens que estejam em status mantido. Você pode usar as propriedades ImageId ou ImageFamily com IDs de imagem válidos."
	},
	"resource_types": ["alicloud_ess_scaling_configuration"],
	"iac_type": "terraform"
}

has_image(resource) if {
	image_id := tf.get_attribute(resource, "image_id", "")
	not tf.is_unknown(image_id)
	image_id != ""
}

has_image(resource) if {
	image_name := tf.get_attribute(resource, "image_name", "")
	not tf.is_unknown(image_name)
	image_name != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ess_scaling_configuration")
	not has_image(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ess_scaling_configuration.%s", [name]),
		"violation_path": ["image_id"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
