package infraguard.rules.aliyun.security_ram_user_mfa_required

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-ram-user-mfa-required",
    "severity": "high",
    "name": {
        "en": "RAM user must require MFA",
        "zh": "RAM 用户必须要求 MFA",
        "ja": "RAM ユーザーは MFA を要求する必要があります",
        "de": "RAM-Benutzer muss MFA erfordern",
        "es": "El usuario RAM debe requerir MFA",
        "fr": "L'utilisateur RAM doit exiger MFA",
        "pt": "O usuário RAM deve exigir MFA",
    },
    "description": {
        "en": "Checks RAM user must require MFA",
        "zh": "检查RAM 用户必须要求 MFA",
        "ja": "RAM ユーザーは MFA を要求する必要がありますことを確認します",
        "de": "Prüft, ob RAM-Benutzer muss MFA erfordern.",
        "es": "Comprueba que el usuario RAM debe requerir MFA.",
        "fr": "Vérifie que l'utilisateur RAM doit exiger MFA.",
        "pt": "Verifica se o usuário RAM deve exigir MFA.",
    },
    "reason": {
        "en": "RAM user must require MFA is not satisfied.",
        "zh": "RAM 用户必须要求 MFA未满足。",
        "ja": "RAM ユーザーは MFA を要求する必要がありますが満たされていません。",
        "de": "RAM-Benutzer muss MFA erfordern ist nicht erfüllt.",
        "es": "No se cumple que el usuario RAM debe requerir MFA.",
        "fr": "La condition suivante n'est pas satisfaite : l'utilisateur RAM doit exiger MFA.",
        "pt": "A condição não foi satisfeita: o usuário RAM deve exigir MFA.",
    },
    "recommendation": {
        "en": "Configure MFABindRequired on ALIYUN::RAM::User to satisfy the policy.",
        "zh": "请在 ALIYUN::RAM::User 上配置 MFABindRequired 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::RAM::User に MFABindRequired を設定してください。",
        "de": "Konfigurieren Sie MFABindRequired für ALIYUN::RAM::User, um die Richtlinie zu erfüllen.",
        "es": "Configure MFABindRequired en ALIYUN::RAM::User para cumplir la política.",
        "fr": "Configurez MFABindRequired sur ALIYUN::RAM::User pour satisfaire la politique.",
        "pt": "Configure MFABindRequired em ALIYUN::RAM::User para atender à política.",
    },
    "resource_types": ["ALIYUN::RAM::User"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::RAM::User")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "MFABindRequired"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.get_property(resource, "MFABindRequired", false) == true
}
