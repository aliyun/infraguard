package infraguard.rules.aliyun.ess_group_health_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-group-health-check",
	"severity": "medium",
	"name": {
		"en": "ESS Scaling Group Health Check",
		"zh": "弹性伸缩组开启 ECS 实例健康检查",
		"ja": "ESS スケーリンググループのヘルスチェック",
		"de": "ESS-Skalierungsgruppe Gesundheitsprüfung",
		"es": "Verificación de Salud del Grupo de Escalado ESS",
		"fr": "Vérification de Santé du Groupe de Mise à l'Échelle ESS",
		"pt": "Verificação de Saúde do Grupo de Escalonamento ESS"
	},
	"description": {
		"en": "ESS scaling groups should enable ECS instance health check to ensure only healthy instances are in service.",
		"zh": "弹性伸缩组开启对 ECS 实例的健康检查，视为合规。",
		"ja": "ESS スケーリンググループは、正常なインスタンスのみがサービスを提供するように、ECS インスタンスのヘルスチェックを有効にする必要があります。",
		"de": "ESS-Skalierungsgruppen sollten ECS-Instanz-Gesundheitsprüfung aktivieren, um sicherzustellen, dass nur gesunde Instanzen im Dienst sind.",
		"es": "Los grupos de escalado ESS deben habilitar la verificación de salud de instancias ECS para asegurar que solo instancias saludables estén en servicio.",
		"fr": "Les groupes de mise à l'échelle ESS doivent activer la vérification de santé des instances ECS pour s'assurer que seules les instances saines sont en service.",
		"pt": "Os grupos de escalonamento ESS devem habilitar a verificação de saúde da instância ECS para garantir que apenas instâncias saudáveis estejam em serviço."
	},
	"reason": {
		"en": "The ESS scaling group does not have health check enabled, which may result in unhealthy instances serving traffic.",
		"zh": "弹性伸缩组未开启健康检查，可能导致异常实例仍在提供服务。",
		"ja": "ESS スケーリンググループでヘルスチェックが有効になっていないため、異常なインスタンスがトラフィックを処理する可能性があります。",
		"de": "Die ESS-Skalierungsgruppe hat keine Gesundheitsprüfung aktiviert, was dazu führen kann, dass ungesunde Instanzen Datenverkehr bedienen.",
		"es": "El grupo de escalado ESS no tiene verificación de salud habilitada, lo que puede resultar en instancias no saludables sirviendo tráfico.",
		"fr": "Le groupe de mise à l'échelle ESS n'a pas de vérification de santé activée, ce qui peut entraîner des instances malsaines servant le trafic.",
		"pt": "O grupo de escalonamento ESS não tem verificação de saúde habilitada, o que pode resultar em instâncias não saudáveis servindo tráfego."
	},
	"recommendation": {
		"en": "Enable health check type for the ESS scaling group by setting HealthCheckType to ECS or configuring HealthCheckTypes.",
		"zh": "为弹性伸缩组启用健康检查，将 HealthCheckType 设置为 ECS 或配置 HealthCheckTypes。",
		"ja": "HealthCheckType を ECS に設定するか、HealthCheckTypes を設定して、ESS スケーリンググループのヘルスチェックタイプを有効にします。",
		"de": "Aktivieren Sie den Gesundheitsprüfungstyp für die ESS-Skalierungsgruppe, indem Sie HealthCheckType auf ECS setzen oder HealthCheckTypes konfigurieren.",
		"es": "Habilite el tipo de verificación de salud para el grupo de escalado ESS estableciendo HealthCheckType en ECS o configurando HealthCheckTypes.",
		"fr": "Activez le type de vérification de santé pour le groupe de mise à l'échelle ESS en définissant HealthCheckType sur ECS ou en configurant HealthCheckTypes.",
		"pt": "Habilite o tipo de verificação de saúde para o grupo de escalonamento ESS definindo HealthCheckType como ECS ou configurando HealthCheckTypes."
	},
	"resource_types": ["ALIYUN::ESS::ScalingGroup"]
}

# Check if scaling group has health check enabled
has_health_check_enabled(resource) if {
	health_check_type := helpers.get_property(resource, "HealthCheckType", "")
	health_check_type != ""
	health_check_type != "NONE"
}

has_health_check_enabled(resource) if {
	health_check_types := helpers.get_property(resource, "HealthCheckTypes", [])
	count(health_check_types) > 0
}

# Deny rule: ESS scaling groups must have health check enabled
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingGroup")
	not has_health_check_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "HealthCheckType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
