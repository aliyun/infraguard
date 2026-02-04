package infraguard.rules.aliyun.metadata_ros_composer_check

import rego.v1

# Rule metadata with i18n support
rule_meta := {
	"id": "metadata-ros-composer-check",
	"severity": "low",
	"name": {
		"en": "Template Metadata ALIYUN::ROS::Composer Check",
		"zh": "模板 Metadata ALIYUN::ROS::Composer 检查",
		"ja": "テンプレートメタデータ ALIYUN::ROS::Composer チェック",
		"de": "Vorlagen-Metadaten ALIYUN::ROS::Composer Prüfung",
		"es": "Verificación de Metadatos de Plantilla ALIYUN::ROS::Composer",
		"fr": "Vérification des Métadonnées de Modèle ALIYUN::ROS::Composer",
		"pt": "Verificação de Metadados de Modelo ALIYUN::ROS::Composer"
	},
	"description": {
		"en": "Template must have Metadata.ALIYUN::ROS::Composer configured. The value must be a dictionary (object).",
		"zh": "模板必须配置 Metadata.ALIYUN::ROS::Composer。该值必须是字典（对象）类型。",
		"ja": "テンプレートには Metadata.ALIYUN::ROS::Composer が設定されている必要があります。値は辞書（オブジェクト）である必要があります。",
		"de": "Vorlage muss Metadata.ALIYUN::ROS::Composer konfiguriert haben. Der Wert muss ein Wörterbuch (Objekt) sein.",
		"es": "La plantilla debe tener Metadata.ALIYUN::ROS::Composer configurado. El valor debe ser un diccionario (objeto).",
		"fr": "Le modèle doit avoir Metadata.ALIYUN::ROS::Composer configuré. La valeur doit être un dictionnaire (objet).",
		"pt": "O modelo deve ter Metadata.ALIYUN::ROS::Composer configurado. O valor deve ser um dicionário (objeto)."
	},
	"reason": {
		"en": "ALIYUN::ROS::Composer is missing or invalid. It must be configured as a dictionary.",
		"zh": "ALIYUN::ROS::Composer 缺失或格式无效。必须配置为字典类型。",
		"ja": "ALIYUN::ROS::Composer が欠落しているか無効です。辞書として設定する必要があります。",
		"de": "ALIYUN::ROS::Composer fehlt oder ist ungültig. Es muss als Wörterbuch konfiguriert werden.",
		"es": "ALIYUN::ROS::Composer falta o no es válido. Debe configurarse como un diccionario.",
		"fr": "ALIYUN::ROS::Composer est manquant ou invalide. Il doit être configuré comme un dictionnaire.",
		"pt": "ALIYUN::ROS::Composer está ausente ou inválido. Deve ser configurado como um dicionário."
	},
	"recommendation": {
		"en": "Use ROS Composer (https://ros.console.aliyun.com/composer) to import your template, configure the architecture diagram, and the composer metadata will be automatically generated.",
		"zh": "使用 ROS 架构编辑器（https://ros.console.aliyun.com/composer）导入模板并配置架构图，系统将自动生成 composer 元数据信息。",
		"ja": "ROS Composer（https://ros.console.aliyun.com/composer）を使用してテンプレートをインポートし、アーキテクチャ図を設定すると、composer メタデータが自動生成されます。",
		"de": "Verwenden Sie ROS Composer (https://ros.console.aliyun.com/composer), um Ihre Vorlage zu importieren, das Architekturdiagramm zu konfigurieren, und die Composer-Metadaten werden automatisch generiert.",
		"es": "Use ROS Composer (https://ros.console.aliyun.com/composer) para importar su plantilla, configurar el diagrama de arquitectura, y los metadatos del compositor se generarán automáticamente.",
		"fr": "Utilisez ROS Composer (https://ros.console.aliyun.com/composer) pour importer votre modèle, configurer le diagramme d'architecture, et les métadonnées du compositeur seront automatiquement générées.",
		"pt": "Use o ROS Composer (https://ros.console.aliyun.com/composer) para importar seu modelo, configurar o diagrama de arquitetura, e os metadados do compositor serão gerados automaticamente."
	},
	"resource_types": []
}

# Check if ALIYUN::ROS::Composer exists and is valid
has_valid_composer if {
	# Check if Metadata exists
	input.Metadata != null

	# Check if ALIYUN::ROS::Composer exists in Metadata
	composer := object.get(input.Metadata, "ALIYUN::ROS::Composer", null)
	composer != null

	# Must be an object (dictionary)
	is_object(composer)
}

# Check template Metadata
deny contains result if {
	# Check if Metadata exists
	input.Metadata == null

	result := {
		"id": rule_meta.id,
		"resource_id": "",
		"violation_path": ["Metadata"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	# Check if Metadata exists
	input.Metadata != null

	# Check if ALIYUN::ROS::Composer is missing
	object.get(input.Metadata, "ALIYUN::ROS::Composer", null) == null

	result := {
		"id": rule_meta.id,
		"resource_id": "",
		"violation_path": ["Metadata", "ALIYUN::ROS::Composer"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	# Check if Metadata exists
	input.Metadata != null

	# Check if ALIYUN::ROS::Composer exists
	composer := object.get(input.Metadata, "ALIYUN::ROS::Composer", null)
	composer != null

	# Check if ALIYUN::ROS::Composer is not an object
	not is_object(composer)

	result := {
		"id": rule_meta.id,
		"resource_id": "",
		"violation_path": ["Metadata", "ALIYUN::ROS::Composer"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
