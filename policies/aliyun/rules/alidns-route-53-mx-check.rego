package infraguard.rules.aliyun.alidns_route_53_mx_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
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
	"resource_types": ["ALIYUN::DNS::DomainRecord"]
}

# Check if a TXT record contains a valid SPF record
has_valid_spf(txt_record) if {
	value := txt_record.Value
	startswith(value, "v=spf1")
}

# Check if an MX record has an associated TXT record with valid SPF
# Valid SPF means TXT record starts with "v=spf1" and contains meaningful mechanisms
mx_has_valid_spf(mx_props, txt_records) if {
	mx_host := mx_props.Value

	some txt_record in txt_records
	txt_value := txt_record.Properties.Value
	has_valid_spf({"Value": txt_value})

	# TXT record should contain the mx host or include mechanism
	contains(txt_value, mx_host)
}

mx_has_valid_spf(mx_props, txt_records) if {
	some txt_record in txt_records
	txt_value := txt_record.Properties.Value
	has_valid_spf({"Value": txt_value})

	# TXT record should contain the include mechanism
	contains(txt_value, "include:")
}

# Get all MX records for a domain
get_mx_records(domain_name) := [record |
	some name, record in helpers.resources_by_type("ALIYUN::DNS::DomainRecord")
	record.Properties.Type == "MX"
	record.Properties.DomainName == domain_name
]

# Get all TXT records for a domain
get_txt_records(domain_name) := [record |
	some name, record in helpers.resources_by_type("ALIYUN::DNS::DomainRecord")
	record.Properties.Type == "TXT"
	record.Properties.DomainName == domain_name
]

deny contains result if {
	some name, domain_resource in helpers.resources_by_type("ALIYUN::DNS::Domain")
	domain_name := domain_resource.Properties.DomainName

	mx_records := get_mx_records(domain_name)
	txt_records := get_txt_records(domain_name)

	# Find MX records that don't have valid SPF TXT records
	some mx_record in mx_records
	mx_record.Properties.Type == "MX"
	not mx_has_valid_spf(mx_record.Properties, txt_records)

	result := {
		"id": rule_meta.id,
		"resource_id": domain_name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
