resource "alicloud_api_gateway_group" "no_ssl" {
  group_name = "no-ssl-group"
}

resource "alicloud_api_gateway_custom_domain" "no_ssl" {
  group_id    = "no_ssl"
  domain_name = "api.example.com"
}
