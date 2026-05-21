resource "alicloud_api_gateway_instance" "secure" {
  https_policy = "HTTPS2_TLS1_2"
  zone_id      = "cn-beijing-MAZ2(f,g)"
}

resource "alicloud_api_gateway_group" "secure" {
  group_name  = "secure-group"
  instance_id = "secure"
}
