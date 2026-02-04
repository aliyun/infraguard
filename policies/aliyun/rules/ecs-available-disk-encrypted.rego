package infraguard.rules.aliyun.ecs_available_disk_encrypted

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-available-disk-encrypted",
	"severity": "high",
	"name": {
		"en": "ECS Disk Encryption Enabled",
		"zh": "可用的磁盘均已加密",
		"ja": "ECS ディスク暗号化が有効",
		"de": "ECS-Festplattenverschlüsselung aktiviert",
		"es": "Cifrado de Disco ECS Habilitado",
		"fr": "Chiffrement de Disque ECS Activé",
		"pt": "Criptografia de Disco ECS Habilitada"
	},
	"description": {
		"en": "Ensures that all ECS disks are encrypted.",
		"zh": "确保所有 ECS 磁盘都已加密。",
		"ja": "すべての ECS ディスクが暗号化されていることを確認します。",
		"de": "Stellt sicher, dass alle ECS-Festplatten verschlüsselt sind.",
		"es": "Garantiza que todos los discos ECS estén cifrados.",
		"fr": "Garantit que tous les disques ECS sont chiffrés.",
		"pt": "Garante que todos os discos ECS estejam criptografados."
	},
	"reason": {
		"en": "Encryption protects data at rest from unauthorized physical access or theft.",
		"zh": "加密可以保护静态数据免受未经授权的物理访问或盗窃。",
		"ja": "暗号化により、保存データが不正な物理アクセスや盗難から保護されます。",
		"de": "Verschlüsselung schützt ruhende Daten vor unbefugtem physischem Zugriff oder Diebstahl.",
		"es": "El cifrado protege los datos en reposo del acceso físico no autorizado o el robo.",
		"fr": "Le chiffrement protège les données au repos contre l'accès physique non autorisé ou le vol.",
		"pt": "A criptografia protege dados em repouso contra acesso físico não autorizado ou roubo."
	},
	"recommendation": {
		"en": "Set 'Encrypted' to true for all ECS disks.",
		"zh": "将所有 ECS 磁盘的'Encrypted'属性设置为 true。",
		"ja": "すべての ECS ディスクの 'Encrypted' を true に設定します。",
		"de": "Setzen Sie 'Encrypted' für alle ECS-Festplatten auf true.",
		"es": "Establezca 'Encrypted' en true para todos los discos ECS.",
		"fr": "Définissez 'Encrypted' sur true pour tous les disques ECS.",
		"pt": "Defina 'Encrypted' como true para todos os discos ECS."
	},
	"resource_types": ["ALIYUN::ECS::Disk"]
}

is_compliant(resource) if {
	helpers.is_true(helpers.get_property(resource, "Encrypted", false))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Encrypted"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
