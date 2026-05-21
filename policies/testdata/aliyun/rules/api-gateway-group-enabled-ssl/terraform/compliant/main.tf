resource "alicloud_api_gateway_group" "ssl" {
  group_name = "ssl-group"
}

resource "alicloud_api_gateway_custom_domain" "ssl" {
  group_id                = "ssl"
  domain_name             = "api.example.com"
  certificate_body        = "-----BEGIN CERTIFICATE----- test -----END CERTIFICATE-----"
  certificate_private_key = "-----BEGIN PRIVATE KEY----- test -----END PRIVATE KEY-----"
}
