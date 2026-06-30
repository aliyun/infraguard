package infraguard.rules.aliyun.security_oss_bucket_logging_configured

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-oss-bucket-logging-configured",
    "severity": "medium",
    "name": {
        "en": "OSS bucket must configure access logging",
        "zh": "OSS Bucket 必须配置访问日志",
        "ja": "OSS バケットはログ記録を設定する必要があります",
        "de": "OSS-Bucket muss Protokollierung konfigurieren",
        "es": "El bucket OSS debe configurar el registro",
        "fr": "Le bucket OSS doit configurer la journalisation",
        "pt": "O bucket OSS deve configurar registro",
    },
    "description": {
        "en": "Checks OSS bucket must configure access logging",
        "zh": "检查OSS Bucket 必须配置访问日志",
        "ja": "OSS バケットはログ記録を設定する必要がありますことを確認します",
        "de": "Prüft, ob OSS-Bucket muss Protokollierung konfigurieren.",
        "es": "Comprueba que el bucket OSS debe configurar el registro.",
        "fr": "Vérifie que le bucket OSS doit configurer la journalisation.",
        "pt": "Verifica se o bucket OSS deve configurar registro.",
    },
    "reason": {
        "en": "OSS bucket must configure access logging is not satisfied.",
        "zh": "OSS Bucket 必须配置访问日志未满足。",
        "ja": "OSS バケットはログ記録を設定する必要がありますが満たされていません。",
        "de": "OSS-Bucket muss Protokollierung konfigurieren ist nicht erfüllt.",
        "es": "No se cumple que el bucket OSS debe configurar el registro.",
        "fr": "La condition suivante n'est pas satisfaite : le bucket OSS doit configurer la journalisation.",
        "pt": "A condição não foi satisfeita: o bucket OSS deve configurar registro.",
    },
    "recommendation": {
        "en": "Configure LoggingConfiguration on ALIYUN::OSS::Bucket to satisfy the policy.",
        "zh": "请在 ALIYUN::OSS::Bucket 上配置 LoggingConfiguration 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::OSS::Bucket に LoggingConfiguration を設定してください。",
        "de": "Konfigurieren Sie LoggingConfiguration für ALIYUN::OSS::Bucket, um die Richtlinie zu erfüllen.",
        "es": "Configure LoggingConfiguration en ALIYUN::OSS::Bucket para cumplir la política.",
        "fr": "Configurez LoggingConfiguration sur ALIYUN::OSS::Bucket pour satisfaire la politique.",
        "pt": "Configure LoggingConfiguration em ALIYUN::OSS::Bucket para atender à política.",
    },
    "resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "LoggingConfiguration"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.has_property(resource, "LoggingConfiguration")
}
