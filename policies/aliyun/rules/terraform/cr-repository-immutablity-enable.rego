package infraguard.rules.terraform.cr_repository_immutablity_enable

import data.infraguard.helpers.terraform as tf
import rego.v1

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
	"resource_types": ["alicloud_cr_ee_repo"],
	"iac_type": "terraform"
}

tag_immutability_enabled(resource) if {
	tf.get_attribute(resource, "tag_immutability", false) == true
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_cr_ee_repo")
	tf.get_attribute(resource, "instance_id", "") != ""
	not tag_immutability_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_cr_ee_repo.%s", [name]),
		"violation_path": ["tag_immutability"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
