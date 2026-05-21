package infraguard.rules.aliyun.cr_repository_immutablity_enable

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "cr-repository-immutablity-enable",
	"severity": "low",
	"name": {
		"en": "Container Registry repository image version is immutable",
		"zh": "容器镜像服务镜像版本为不可变",
		"ja": "コンテナレジストリリポジトリイメージバージョンが不変",
		"de": "Container Registry Repository Bildversion ist unveränderlich",
		"es": "La Versión de Imagen del Repositorio del Registro de Contenedores es Inmutable",
		"fr": "La Version d'Image du Dépôt du Registre de Conteneurs est Immutable",
		"pt": "A Versão da Imagem do Repositório do Registro de Contêineres é Imutável"
	},
	"description": {
		"en": "Container Registry repository image version is immutable, considered compliant.",
		"zh": "容器镜像服务镜像版本为不可变,视为合规。",
		"ja": "コンテナレジストリリポジトリイメージバージョンが不変であり、準拠と見なされます。",
		"de": "Container Registry Repository Bildversion ist unveränderlich, was als konform gilt.",
		"es": "La versión de imagen del repositorio del Registro de Contenedores es inmutable, considerado conforme.",
		"fr": "La version d'image du dépôt du Registre de Conteneurs est immuable, considéré comme conforme.",
		"pt": "A versão da imagem do repositório do Registro de Contêineres é imutável, considerado conforme."
	},
	"reason": {
		"en": "Container Registry repository image version is not immutable",
		"zh": "容器镜像服务镜像版本不是不可变的",
		"ja": "コンテナレジストリリポジトリイメージバージョンが不変ではない",
		"de": "Container Registry Repository Bildversion ist nicht unveränderlich",
		"es": "La versión de imagen del repositorio del Registro de Contenedores no es inmutable",
		"fr": "La version d'image du dépôt du Registre de Conteneurs n'est pas immuable",
		"pt": "A versão da imagem do repositório do Registro de Contêineres não é imutável"
	},
	"recommendation": {
		"en": "Enable tag immutability for Container Registry repository to prevent image tags from being overwritten",
		"zh": "为容器镜像服务仓库启用标签不可变性以防止镜像标签被覆盖",
		"ja": "イメージタグが上書きされないように、コンテナレジストリリポジトリのタグ不変性を有効にします",
		"de": "Aktivieren Sie Tag-Unveränderlichkeit für Container Registry Repository, um zu verhindern, dass Bild-Tags überschrieben werden",
		"es": "Habilite la inmutabilidad de etiquetas para el repositorio del Registro de Contenedores para evitar que las etiquetas de imagen se sobrescriban",
		"fr": "Activez l'immuabilité des balises pour le dépôt du Registre de Conteneurs pour empêcher l'écrasement des balises d'image",
		"pt": "Habilite a imutabilidade de tags para o repositório do Registro de Contêineres para evitar que tags de imagem sejam sobrescritas"
	},
	"resource_types": ["ALIYUN::CR::Repository"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CR::Repository")

	# Check if TagImmutability is enabled
	# Only applicable when InstanceId is specified (Enterprise Edition)
	has_instance := helpers.has_property(resource, "InstanceId")
	has_instance

	tag_immutability := helpers.get_property(resource, "TagImmutability", false)
	not helpers.is_true(tag_immutability)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
