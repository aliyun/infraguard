resource "alicloud_fc_service" "compliant" {
  name            = "my-service"
  internet_access = true
}

resource "alicloud_fc_custom_domain" "domain" {
  domain_name = "example.com"
  protocol    = "HTTPS"
}
