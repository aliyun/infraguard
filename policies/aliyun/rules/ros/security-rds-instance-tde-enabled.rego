package infraguard.rules.aliyun.security_rds_instance_tde_enabled

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-rds-instance-tde-enabled",
    "severity": "high",
    "name": {
        "en": "RDS instance must enable TDE",
        "zh": "RDS 实例必须启用 TDE",
        "ja": "RDS インスタンスは TDE を有効にする必要があります",
        "de": "RDS-Instanz muss TDE aktivieren",
        "es": "La instancia RDS debe habilitar TDE",
        "fr": "L'instance RDS doit activer TDE",
        "pt": "A instância RDS deve habilitar TDE",
    },
    "description": {
        "en": "Checks RDS instance must enable TDE",
        "zh": "检查RDS 实例必须启用 TDE",
        "ja": "RDS インスタンスは TDE を有効にする必要がありますことを確認します",
        "de": "Prüft, ob RDS-Instanz muss TDE aktivieren.",
        "es": "Comprueba que la instancia RDS debe habilitar TDE.",
        "fr": "Vérifie que l'instance RDS doit activer TDE.",
        "pt": "Verifica se a instância RDS deve habilitar TDE.",
    },
    "reason": {
        "en": "RDS instance must enable TDE is not satisfied.",
        "zh": "RDS 实例必须启用 TDE未满足。",
        "ja": "RDS インスタンスは TDE を有効にする必要がありますが満たされていません。",
        "de": "RDS-Instanz muss TDE aktivieren ist nicht erfüllt.",
        "es": "No se cumple que la instancia RDS debe habilitar TDE.",
        "fr": "La condition suivante n'est pas satisfaite : l'instance RDS doit activer TDE.",
        "pt": "A condição não foi satisfeita: a instância RDS deve habilitar TDE.",
    },
    "recommendation": {
        "en": "Configure TDEStatus on ALIYUN::RDS::DBInstance to satisfy the policy.",
        "zh": "请在 ALIYUN::RDS::DBInstance 上配置 TDEStatus 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::RDS::DBInstance に TDEStatus を設定してください。",
        "de": "Konfigurieren Sie TDEStatus für ALIYUN::RDS::DBInstance, um die Richtlinie zu erfüllen.",
        "es": "Configure TDEStatus en ALIYUN::RDS::DBInstance para cumplir la política.",
        "fr": "Configurez TDEStatus sur ALIYUN::RDS::DBInstance pour satisfaire la politique.",
        "pt": "Configure TDEStatus em ALIYUN::RDS::DBInstance para atender à política.",
    },
    "resource_types": ["ALIYUN::RDS::DBInstance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "TDEStatus"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.get_property(resource, "TDEStatus", "") == "Enabled"
}
