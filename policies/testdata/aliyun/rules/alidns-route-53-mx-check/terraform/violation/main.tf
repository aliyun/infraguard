resource "alicloud_alidns_domain" "example" {
  domain_name = "example.com"
}

resource "alicloud_alidns_record" "mx" {
  domain_name = "example.com"
  rr          = "@"
  type        = "MX"
  priority    = 10
  value       = "mail.example.com"
}

resource "alicloud_alidns_record" "spf_without_mechanism" {
  domain_name = "example.com"
  rr          = "@"
  type        = "TXT"
  value       = "v=spf1 -all"
}
