package infraguard.rules.aliyun.security_rds_instance_ssl_required

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-rds-instance-ssl-required",
    "severity": "high",
    "name": {
        "en": "RDS instance must configure SSL",
        "zh": "RDS 实例必须配置 SSL",
        "ja": "RDS インスタンスは SSL を設定する必要があります",
        "de": "RDS-Instanz muss SSL konfigurieren",
        "es": "La instancia RDS debe configurar SSL",
        "fr": "L'instance RDS doit configurer SSL",
        "pt": "A instância RDS deve configurar SSL",
    },
    "description": {
        "en": "Checks RDS instance must configure SSL",
        "zh": "检查RDS 实例必须配置 SSL",
        "ja": "RDS インスタンスは SSL を設定する必要がありますことを確認します",
        "de": "Prüft, ob RDS-Instanz muss SSL konfigurieren.",
        "es": "Comprueba que la instancia RDS debe configurar SSL.",
        "fr": "Vérifie que l'instance RDS doit configurer SSL.",
        "pt": "Verifica se a instância RDS deve configurar SSL.",
    },
    "reason": {
        "en": "RDS instance must configure SSL is not satisfied.",
        "zh": "RDS 实例必须配置 SSL未满足。",
        "ja": "RDS インスタンスは SSL を設定する必要がありますが満たされていません。",
        "de": "RDS-Instanz muss SSL konfigurieren ist nicht erfüllt.",
        "es": "No se cumple que la instancia RDS debe configurar SSL.",
        "fr": "La condition suivante n'est pas satisfaite : l'instance RDS doit configurer SSL.",
        "pt": "A condição não foi satisfeita: a instância RDS deve configurar SSL.",
    },
    "recommendation": {
        "en": "Configure SSLSetting on ALIYUN::RDS::DBInstance to satisfy the policy.",
        "zh": "请在 ALIYUN::RDS::DBInstance 上配置 SSLSetting 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::RDS::DBInstance に SSLSetting を設定してください。",
        "de": "Konfigurieren Sie SSLSetting für ALIYUN::RDS::DBInstance, um die Richtlinie zu erfüllen.",
        "es": "Configure SSLSetting en ALIYUN::RDS::DBInstance para cumplir la política.",
        "fr": "Configurez SSLSetting sur ALIYUN::RDS::DBInstance pour satisfaire la politique.",
        "pt": "Configure SSLSetting em ALIYUN::RDS::DBInstance para atender à política.",
    },
    "resource_types": ["ALIYUN::RDS::DBInstance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "SSLSetting"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.has_property(resource, "SSLSetting")
}
