package infraguard.rules.aliyun.security_oss_bucket_encryption_configured

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-oss-bucket-encryption-configured",
    "severity": "high",
    "name": {
        "en": "OSS bucket must configure server-side encryption",
        "zh": "OSS Bucket 必须配置服务端加密",
        "ja": "OSS バケットは暗号化を設定する必要があります",
        "de": "OSS-Bucket muss Verschlüsselung konfigurieren",
        "es": "El bucket OSS debe configurar el cifrado",
        "fr": "Le bucket OSS doit configurer le chiffrement",
        "pt": "O bucket OSS deve configurar criptografia",
    },
    "description": {
        "en": "Checks OSS bucket must configure server-side encryption",
        "zh": "检查OSS Bucket 必须配置服务端加密",
        "ja": "OSS バケットは暗号化を設定する必要がありますことを確認します",
        "de": "Prüft, ob OSS-Bucket muss Verschlüsselung konfigurieren.",
        "es": "Comprueba que el bucket OSS debe configurar el cifrado.",
        "fr": "Vérifie que le bucket OSS doit configurer le chiffrement.",
        "pt": "Verifica se o bucket OSS deve configurar criptografia.",
    },
    "reason": {
        "en": "OSS bucket must configure server-side encryption is not satisfied.",
        "zh": "OSS Bucket 必须配置服务端加密未满足。",
        "ja": "OSS バケットは暗号化を設定する必要がありますが満たされていません。",
        "de": "OSS-Bucket muss Verschlüsselung konfigurieren ist nicht erfüllt.",
        "es": "No se cumple que el bucket OSS debe configurar el cifrado.",
        "fr": "La condition suivante n'est pas satisfaite : le bucket OSS doit configurer le chiffrement.",
        "pt": "A condição não foi satisfeita: o bucket OSS deve configurar criptografia.",
    },
    "recommendation": {
        "en": "Configure ServerSideEncryptionConfiguration on ALIYUN::OSS::Bucket to satisfy the policy.",
        "zh": "请在 ALIYUN::OSS::Bucket 上配置 ServerSideEncryptionConfiguration 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::OSS::Bucket に ServerSideEncryptionConfiguration を設定してください。",
        "de": "Konfigurieren Sie ServerSideEncryptionConfiguration für ALIYUN::OSS::Bucket, um die Richtlinie zu erfüllen.",
        "es": "Configure ServerSideEncryptionConfiguration en ALIYUN::OSS::Bucket para cumplir la política.",
        "fr": "Configurez ServerSideEncryptionConfiguration sur ALIYUN::OSS::Bucket pour satisfaire la politique.",
        "pt": "Configure ServerSideEncryptionConfiguration em ALIYUN::OSS::Bucket para atender à política.",
    },
    "resource_types": ["ALIYUN::OSS::Bucket"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "ServerSideEncryptionConfiguration"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.has_property(resource, "ServerSideEncryptionConfiguration")
}
