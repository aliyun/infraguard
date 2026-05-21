package infraguard.rules.terraform.ecs_instance_image_expired_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-instance-image-expired-check",
	"severity": "medium",
	"name": {
		"en": "ECS Instance Image Expired Check",
		"zh": "ECS 实例镜像过期检测",
		"ja": "ECS インスタンスイメージの有効期限チェック",
		"de": "ECS-Instanz Bild-Ablaufprüfung",
		"es": "Verificación de Expiración de Imagen de Instancia ECS",
		"fr": "Vérification d'Expiration d'Image d'Instance ECS",
		"pt": "Verificação de Expiração de Imagem de Instância ECS"
	},
	"description": {
		"en": "Ensures that the image used by the ECS instance has not expired.",
		"zh": "确保 ECS 实例使用的镜像未过期。",
		"ja": "ECS インスタンスで使用されているイメージが期限切れでないことを確認します。",
		"de": "Stellt sicher, dass das von der ECS-Instanz verwendete Bild nicht abgelaufen ist.",
		"es": "Garantiza que la imagen usada por la instancia ECS no haya expirado.",
		"fr": "Garantit que l'image utilisée par l'instance ECS n'a pas expiré.",
		"pt": "Garante que a imagem usada pela instância ECS não tenha expirado."
	},
	"reason": {
		"en": "Using an expired image may lead to security vulnerabilities and lack of support.",
		"zh": "使用过期的镜像可能导致安全漏洞和缺乏技术支持。",
		"ja": "期限切れのイメージを使用すると、セキュリティの脆弱性やサポートの欠如につながる可能性があります。",
		"de": "Die Verwendung eines abgelaufenen Bildes kann zu Sicherheitslücken und fehlender Unterstützung führen.",
		"es": "Usar una imagen expirada puede llevar a vulnerabilidades de seguridad y falta de soporte.",
		"fr": "Utiliser une image expirée peut entraîner des vulnérabilités de sécurité et un manque de support.",
		"pt": "Usar uma imagem expirada pode levar a vulnerabilidades de segurança e falta de suporte."
	},
	"recommendation": {
		"en": "Update the ECS instance to use a supported, non-expired image.",
		"zh": "更新 ECS 实例以使用受支持、未过期的镜像。",
		"ja": "ECS インスタンスを更新して、サポートされている期限切れでないイメージを使用します。",
		"de": "Aktualisieren Sie die ECS-Instanz, um ein unterstütztes, nicht abgelaufenes Bild zu verwenden.",
		"es": "Actualice la instancia ECS para usar una imagen compatible y no expirada.",
		"fr": "Mettez à jour l'instance ECS pour utiliser une image prise en charge et non expirée.",
		"pt": "Atualize a instância ECS para usar uma imagem suportada e não expirada."
	},
	"resource_types": ["alicloud_instance"],
	"iac_type": "terraform"
}

violation_for(name) := {
	"id": rule_meta.id,
	"resource_id": sprintf("alicloud_instance.%s", [name]),
	"meta": {
		"severity": rule_meta.severity,
		"reason": rule_meta.reason,
		"recommendation": rule_meta.recommendation,
	},
}

expired_image_prefixes := ["centos_6", "centos_5", "ubuntu_14", "ubuntu_12", "debian_8", "windows_2008", "windows_2012"]

uses_expired_image(image_id) if {
	some prefix in expired_image_prefixes
	startswith(lower(image_id), prefix)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	image_id := tf.get_attribute(resource, "image_id", "")
	not tf.is_unknown(image_id)
	image_id != ""
	uses_expired_image(image_id)
	violation := violation_for(name)
}
