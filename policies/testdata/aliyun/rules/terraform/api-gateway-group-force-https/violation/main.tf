resource "alicloud_api_gateway_group" "plain" {
  group_name = "plain-group"
}

resource "alicloud_api_gateway_custom_domain" "plain" {
  group_id    = "plain"
  domain_name = "api.example.com"
}
