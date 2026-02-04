package infraguard.rules.aliyun.eci_container_group_volumn_mounts

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "eci-container-group-volumn-mounts",
	"severity": "low",
	"name": {
		"en": "ECI Volume Mounting Check",
		"zh": "ECI 容器组挂载卷核查",
		"ja": "ECI ボリュームマウントチェック",
		"de": "ECI-Volumen-Mount-Prüfung",
		"es": "Verificación de Montaje de Volumen ECI",
		"fr": "Vérification du Montage de Volume ECI",
		"pt": "Verificação de Montagem de Volume ECI"
	},
	"description": {
		"en": "Ensures ECI container groups have volumes mounted for persistent data storage.",
		"zh": "确保 ECI 容器组挂载了用于持久化数据存储的卷。",
		"ja": "ECI コンテナグループに永続データストレージ用のボリュームがマウントされていることを確認します。",
		"de": "Stellt sicher, dass ECI-Containergruppen Volumes für persistente Datenspeicherung gemountet haben.",
		"es": "Garantiza que los grupos de contenedores ECI tengan volúmenes montados para almacenamiento de datos persistente.",
		"fr": "Garantit que les groupes de conteneurs ECI ont des volumes montés pour le stockage de données persistant.",
		"pt": "Garante que os grupos de contêineres ECI tenham volumes montados para armazenamento de dados persistente."
	},
	"reason": {
		"en": "Stateless containers may lose critical data upon restart if volumes are not mounted.",
		"zh": "如果未挂载卷，无状态容器在重启时可能会丢失关键数据。",
		"ja": "ボリュームがマウントされていない場合、ステートレスコンテナは再起動時に重要なデータを失う可能性があります。",
		"de": "Zustandslose Container können bei Neustart kritische Daten verlieren, wenn keine Volumes gemountet sind.",
		"es": "Los contenedores sin estado pueden perder datos críticos al reiniciar si no se montan volúmenes.",
		"fr": "Les conteneurs sans état peuvent perdre des données critiques lors du redémarrage si les volumes ne sont pas montés.",
		"pt": "Contêineres sem estado podem perder dados críticos ao reiniciar se os volumes não estiverem montados."
	},
	"recommendation": {
		"en": "Configure volumes and volume mounts for the ECI container group.",
		"zh": "为 ECI 容器组配置卷及卷挂载。",
		"ja": "ECI コンテナグループのボリュームとボリュームマウントを設定します。",
		"de": "Konfigurieren Sie Volumes und Volume-Mounts für die ECI-Containergruppe.",
		"es": "Configure volúmenes y montajes de volúmenes para el grupo de contenedores ECI.",
		"fr": "Configurez les volumes et les montages de volumes pour le groupe de conteneurs ECI.",
		"pt": "Configure volumes e montagens de volumes para o grupo de contêineres ECI."
	},
	"resource_types": ["ALIYUN::ECI::ContainerGroup"]
}

is_compliant(resource) if {
	volumes := helpers.get_property(resource, "Volume", [])
	count(volumes) > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECI::ContainerGroup")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Volume"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
