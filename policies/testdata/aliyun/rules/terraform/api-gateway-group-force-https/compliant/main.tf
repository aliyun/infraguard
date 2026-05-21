resource "alicloud_api_gateway_group" "forced" {
  group_name = "forced-group"
}

resource "alicloud_api_gateway_custom_domain" "forced" {
  group_id                = "forced"
  domain_name             = "api.example.com"
  force_https             = true
  certificate_body        = "-----BEGIN CERTIFICATE----- test -----END CERTIFICATE-----"
  certificate_private_key = "-----BEGIN PRIVATE KEY----- test -----END PRIVATE KEY-----"
}
