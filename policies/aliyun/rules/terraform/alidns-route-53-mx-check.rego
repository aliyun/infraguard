package infraguard.rules.terraform.alidns_route_53_mx_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "alidns-route-53-mx-check",
	"severity": "high",
	"name": {
		"en": "DNS MX Record Has Valid SPF in Associated TXT Record",
		"zh": "DNS 域名 MX 记录关联的 TXT 记录包含有效的 SPF 值",
		"ja": "DNS MX レコードに関連付けられた TXT レコードに有効な SPF がある",
		"de": "DNS MX-Eintrag hat gültiges SPF in zugehörigem TXT-Eintrag",
		"es": "Registro MX de DNS Tiene SPF Válido en Registro TXT Asociado",
		"fr": "L'Enregistrement MX DNS a un SPF Valide dans l'Enregistrement TXT Associé",
		"pt": "Registro MX DNS Tem SPF Válido no Registro TXT Associado"
	},
	"description": {
		"en": "Ensures that MX records have associated TXT records with valid SPF values for email validation.",
		"zh": "对于每个 MX 记录，检查关联的 TXT 记录是否包含有效的 SPF 值,只要 MX 记录有至少一个具有有效 SPF 值的关联 TXT 记录，则视为合规。",
		"ja": "MX レコードに、メール検証用の有効な SPF 値を持つ関連 TXT レコードがあることを確認します。",
		"de": "Stellt sicher, dass MX-Einträge zugehörige TXT-Einträge mit gültigen SPF-Werten für die E-Mail-Validierung haben.",
		"es": "Garantiza que los registros MX tengan registros TXT asociados con valores SPF válidos para validación de correo electrónico.",
		"fr": "Garantit que les enregistrements MX ont des enregistrements TXT associés avec des valeurs SPF valides pour la validation des e-mails.",
		"pt": "Garante que os registros MX tenham registros TXT associados com valores SPF válidos para validação de e-mail."
	},
	"reason": {
		"en": "MX records without valid SPF configuration may be vulnerable to email spoofing.",
		"zh": "MX 记录未配置有效的 SPF 值，可能导致邮件伪造风险。",
		"ja": "有効な SPF 設定がない MX レコードは、メールスプーフィングに対して脆弱である可能性があります。",
		"de": "MX-Einträge ohne gültige SPF-Konfiguration können anfällig für E-Mail-Spoofing sein.",
		"es": "Los registros MX sin configuración SPF válida pueden ser vulnerables a suplantación de correo electrónico.",
		"fr": "Les enregistrements MX sans configuration SPF valide peuvent être vulnérables à l'usurpation d'e-mail.",
		"pt": "Registros MX sem configuração SPF válida podem ser vulneráveis à falsificação de e-mail."
	},
	"recommendation": {
		"en": "Configure TXT records with valid SPF values for each MX record.",
		"zh": "为每个 MX 记录配置包含有效 SPF 值的 TXT 记录。",
		"ja": "各 MX レコードに対して有効な SPF 値を持つ TXT レコードを設定します。",
		"de": "Konfigurieren Sie TXT-Einträge mit gültigen SPF-Werten für jeden MX-Eintrag.",
		"es": "Configure registros TXT con valores SPF válidos para cada registro MX.",
		"fr": "Configurez les enregistrements TXT avec des valeurs SPF valides pour chaque enregistrement MX.",
		"pt": "Configure registros TXT com valores SPF válidos para cada registro MX."
	},
	"resource_types": ["alicloud_alidns_record"],
	"iac_type": "terraform"
}

record_type(resource) := upper(tf.get_attribute(resource, "type", ""))

same_domain(left, right) if {
	left_domain := tf.get_attribute(left, "domain_name", "")
	right_domain := tf.get_attribute(right, "domain_name", "")
	not tf.is_unknown(left_domain)
	not tf.is_unknown(right_domain)
	left_domain == right_domain
}

has_valid_spf(txt_record) if {
	txt_value := tf.get_attribute(txt_record, "value", "")
	startswith(txt_value, "v=spf1")
}

mx_has_valid_spf(mx_record, txt_records) if {
	mx_host := tf.get_attribute(mx_record, "value", "")
	some _, txt_record in txt_records
	same_domain(mx_record, txt_record)
	record_type(txt_record) == "TXT"
	has_valid_spf(txt_record)
	contains(tf.get_attribute(txt_record, "value", ""), mx_host)
}

mx_has_valid_spf(mx_record, txt_records) if {
	some _, txt_record in txt_records
	same_domain(mx_record, txt_record)
	record_type(txt_record) == "TXT"
	has_valid_spf(txt_record)
	contains(tf.get_attribute(txt_record, "value", ""), "include:")
}

deny contains violation if {
	records := tf.resources_by_type("alicloud_alidns_record")
	some name, mx_record in records
	record_type(mx_record) == "MX"
	not tf.is_unknown(tf.get_attribute(mx_record, "domain_name", ""))
	not mx_has_valid_spf(mx_record, records)

	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_alidns_record.%s", [name]),
		"violation_path": ["value"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
