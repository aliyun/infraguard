resource "alicloud_fc_custom_domain" "compliant" {
  domain_name = "example.com"
  protocol    = "HTTPS"

  cert_config {
    cert_name   = "test-cert"
    certificate = "-----BEGIN CERTIFICATE----- test -----END CERTIFICATE-----"
    private_key = "-----BEGIN PRIVATE KEY----- test -----END PRIVATE KEY-----"
  }
}
