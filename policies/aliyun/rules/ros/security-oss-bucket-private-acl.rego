package infraguard.rules.aliyun.security_oss_bucket_private_acl

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-oss-bucket-private-acl",
    "severity": "high",
    "name": {
        "en": "OSS bucket ACL must be private",
        "zh": "OSS Bucket ACL 必须为私有",
        "ja": "OSS バケット ACL は private である必要があります",
        "de": "OSS-Bucket-ACL muss privat sein",
        "es": "La ACL del bucket OSS debe ser privada",
        "fr": "L'ACL du bucket OSS doit être privée",
        "pt": "A ACL do bucket OSS deve ser privada",
    },
    "description": {
        "en": "Checks OSS bucket ACL must be private",
        "zh": "检查OSS Bucket ACL 必须为私有",
        "ja": "OSS バケット ACL は private である必要がありますことを確認します",
        "de": "Prüft, ob OSS-Bucket-ACL muss privat sein.",
        "es": "Comprueba que la ACL del bucket OSS debe ser privada.",
        "fr": "Vérifie que l'ACL du bucket OSS doit être privée.",
        "pt": "Verifica se a ACL do bucket OSS deve ser privada.",
    },
    "reason": {
        "en": "OSS bucket ACL must be private is not satisfied.",
        "zh": "OSS Bucket ACL 必须为私有未满足。",
        "ja": "OSS バケット ACL は private である必要がありますが満たされていません。",
        "de": "OSS-Bucket-ACL muss privat sein ist nicht erfüllt.",
        "es": "No se cumple que la ACL del bucket OSS debe ser privada.",
        "fr": "La condition suivante n'est pas satisfaite : l'ACL du bucket OSS doit être privée.",
        "pt": "A condição não foi satisfeita: a ACL do bucket OSS deve ser privada.",
    },
    "recommendation": {
        "en": "Configure AccessControl on ALIYUN::OSS::Bucket to satisfy the policy.",
        "zh": "请在 ALIYUN::OSS::Bucket 上配置 AccessControl 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::OSS::Bucket に AccessControl を設定してください。",
        "de": "Konfigurieren Sie AccessControl für ALIYUN::OSS::Bucket, um die Richtlinie zu erfüllen.",
        "es": "Configure AccessControl en ALIYUN::OSS::Bucket para cumplir la política.",
        "fr": "Configurez AccessControl sur ALIYUN::OSS::Bucket pour satisfaire la politique.",
        "pt": "Configure AccessControl em ALIYUN::OSS::Bucket para atender à política.",
    },
    "resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "AccessControl"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.get_property(resource, "AccessControl", "") == "private"
}
