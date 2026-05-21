package infraguard.rules.terraform.maxcompute_project_encryption_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "maxcompute-project-encryption-enabled",
	"severity": "high",
	"name": {
		"en": "MaxCompute Project Encryption Enabled",
		"zh": "MaxCompute 项目已启用加密",
		"ja": "MaxCompute プロジェクト暗号化が有効",
		"de": "MaxCompute-Projekt Verschlüsselung aktiviert",
		"es": "Cifrado del Proyecto MaxCompute Habilitado",
		"fr": "Chiffrement du Projet MaxCompute Activé",
		"pt": "Criptografia do Projeto MaxCompute Habilitada"
	},
	"description": {
		"en": "Ensures MaxCompute projects have encryption enabled to protect data at rest.",
		"zh": "确保 MaxCompute 项目已启用加密以保护静态数据。",
		"ja": "MaxCompute プロジェクトで保存時のデータ保護のために暗号化が有効になっていることを確認します。",
		"de": "Stellt sicher, dass MaxCompute-Projekte Verschlüsselung aktiviert haben, um gespeicherte Daten zu schützen.",
		"es": "Garantiza que los proyectos MaxCompute tengan cifrado habilitado para proteger los datos en reposo.",
		"fr": "Garantit que les projets MaxCompute ont le chiffrement activé pour protéger les données au repos.",
		"pt": "Garante que os projetos MaxCompute tenham criptografia habilitada para proteger dados em repouso."
	},
	"reason": {
		"en": "The MaxCompute project does not have encryption enabled, leaving data at rest unprotected.",
		"zh": "MaxCompute 项目未启用加密，静态数据未受保护。",
		"ja": "MaxCompute プロジェクトで暗号化が有効になっておらず、保存時のデータが保護されていません。",
		"de": "Das MaxCompute-Projekt hat keine Verschlüsselung aktiviert, wodurch gespeicherte Daten ungeschützt sind.",
		"es": "El proyecto MaxCompute no tiene cifrado habilitado, dejando los datos en reposo sin protección.",
		"fr": "Le projet MaxCompute n'a pas le chiffrement activé, laissant les données au repos non protégées.",
		"pt": "O projeto MaxCompute não tem criptografia habilitada, deixando dados em repouso desprotegidos."
	},
	"recommendation": {
		"en": "Enable encryption on the MaxCompute project by setting encryption_enable to true.",
		"zh": "通过将 encryption_enable 设置为 true 来启用 MaxCompute 项目的加密。",
		"ja": "encryption_enable を true に設定して MaxCompute プロジェクトの暗号化を有効にします。",
		"de": "Aktivieren Sie die Verschlüsselung im MaxCompute-Projekt, indem Sie encryption_enable auf true setzen.",
		"es": "Habilite el cifrado en el proyecto MaxCompute configurando encryption_enable como true.",
		"fr": "Activez le chiffrement sur le projet MaxCompute en définissant encryption_enable sur true.",
		"pt": "Habilite a criptografia no projeto MaxCompute definindo encryption_enable como true."
	},
	"resource_types": ["alicloud_maxcompute_project"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_maxcompute_project")
	encryption_enable := tf.get_attribute(resource, "encryption_enable", false)
	not tf.is_unknown(encryption_enable)
	encryption_enable != true
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_maxcompute_project.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
