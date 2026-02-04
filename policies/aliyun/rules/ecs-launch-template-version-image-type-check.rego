package infraguard.rules.aliyun.ecs_launch_template_version_image_type_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-launch-template-version-image-type-check",
	"severity": "medium",
	"name": {
		"en": "Launch Template Image Type Check",
		"zh": "启动模板镜像来源核查",
		"ja": "起動テンプレートイメージタイプチェック",
		"de": "Startvorlage Bildtypprüfung",
		"es": "Verificación de Tipo de Imagen de Plantilla de Inicio",
		"fr": "Vérification du Type d'Image du Modèle de Démarrage",
		"pt": "Verificação de Tipo de Imagem do Modelo de Inicialização"
	},
	"description": {
		"en": "Ensures ECS launch templates use authorized image types.",
		"zh": "确保 ECS 启动模板使用授权的镜像类型。",
		"ja": "ECS 起動テンプレートが承認されたイメージタイプを使用していることを確認します。",
		"de": "Stellt sicher, dass ECS-Startvorlagen autorisierte Bildtypen verwenden.",
		"es": "Garantiza que las plantillas de inicio ECS usen tipos de imagen autorizados.",
		"fr": "Garantit que les modèles de démarrage ECS utilisent des types d'image autorisés.",
		"pt": "Garante que os modelos de inicialização ECS usem tipos de imagem autorizados."
	},
	"reason": {
		"en": "Restricting image sources in templates ensures consistent security baselines.",
		"zh": "在模板中限制镜像来源可确保一致的安全基线。",
		"ja": "テンプレートでイメージソースを制限することで、一貫したセキュリティベースラインが確保されます。",
		"de": "Die Einschränkung von Bildquellen in Vorlagen gewährleistet konsistente Sicherheitsbaselines.",
		"es": "Restringir las fuentes de imagen en las plantillas garantiza líneas base de seguridad consistentes.",
		"fr": "Restreindre les sources d'image dans les modèles garantit des lignes de base de sécurité cohérentes.",
		"pt": "Restringir fontes de imagem em modelos garante linhas de base de segurança consistentes."
	},
	"recommendation": {
		"en": "Update the launch template to use authorized images.",
		"zh": "更新启动模板以使用授权镜像。",
		"ja": "承認されたイメージを使用するように起動テンプレートを更新します。",
		"de": "Aktualisieren Sie die Startvorlage, um autorisierte Bilder zu verwenden.",
		"es": "Actualice la plantilla de inicio para usar imágenes autorizadas.",
		"fr": "Mettez à jour le modèle de démarrage pour utiliser des images autorisées.",
		"pt": "Atualize o modelo de inicialização para usar imagens autorizadas."
	},
	"resource_types": ["ALIYUN::ECS::LaunchTemplate"]
}

is_compliant(resource) if {
	# Check ImageId directly in Properties
	helpers.get_property(resource, "ImageId", null) != null
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::LaunchTemplate")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ImageId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
