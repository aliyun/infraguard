resource "alicloud_api_gateway_group" "bound" {
  group_name = "bound-group"
}

resource "alicloud_api_gateway_custom_domain" "bound" {
  group_id    = "bound"
  domain_name = "api.example.com"
}
