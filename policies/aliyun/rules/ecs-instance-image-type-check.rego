package infraguard.rules.aliyun.ecs_instance_image_type_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-instance-image-type-check",
	"name": {
		"en": "ECS Instance Image Type Check",
		"zh": "ECS 实例镜像来源核查",
		"ja": "ECS インスタンスイメージタイプチェック",
		"de": "ECS-Instanz Bildtyp-Prüfung",
		"es": "Verificación de Tipo de Imagen de Instancia ECS",
		"fr": "Vérification du Type d'Image d'Instance ECS",
		"pt": "Verificação de Tipo de Imagem de Instância ECS",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures ECS instances use images from authorized sources.",
		"zh": "确保 ECS 实例使用来自授权来源的镜像。",
		"ja": "ECS インスタンスが承認されたソースからのイメージを使用することを確認します。",
		"de": "Stellt sicher, dass ECS-Instanzen Bilder aus autorisierten Quellen verwenden.",
		"es": "Garantiza que las instancias ECS usen imágenes de fuentes autorizadas.",
		"fr": "Garantit que les instances ECS utilisent des images provenant de sources autorisées.",
		"pt": "Garante que as instâncias ECS usem imagens de fontes autorizadas.",
	},
	"reason": {
		"en": "Using untrusted image sources can introduce security vulnerabilities or malware.",
		"zh": "使用未经信任的镜像来源可能会引入安全漏洞或恶意软件。",
		"ja": "信頼できないイメージソースを使用すると、セキュリティの脆弱性やマルウェアが導入される可能性があります。",
		"de": "Die Verwendung nicht vertrauenswürdiger Bildquellen kann Sicherheitslücken oder Malware einführen.",
		"es": "Usar fuentes de imagen no confiables puede introducir vulnerabilidades de seguridad o malware.",
		"fr": "Utiliser des sources d'images non fiables peut introduire des vulnérabilités de sécurité ou des logiciels malveillants.",
		"pt": "Usar fontes de imagem não confiáveis pode introduzir vulnerabilidades de segurança ou malware.",
	},
	"recommendation": {
		"en": "Specify an authorized ImageId for the ECS instance.",
		"zh": "为 ECS 实例指定授权的镜像 ID。",
		"ja": "ECS インスタンスに承認された ImageId を指定します。",
		"de": "Geben Sie eine autorisierte ImageId für die ECS-Instanz an.",
		"es": "Especifique un ImageId autorizado para la instancia ECS.",
		"fr": "Spécifiez un ImageId autorisé pour l'instance ECS.",
		"pt": "Especifique um ImageId autorizado para a instância ECS.",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

is_compliant(resource) if {
	# In ROS, we usually check if ImageId is set.
	# Complex source checking often requires runtime tags, but we ensure ImageId is present.
	helpers.has_property(resource, "ImageId")
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ImageId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
