resource "alicloud_api_gateway_instance" "legacy" {
  https_policy = "HTTPS1_1_TLS1_0"
  zone_id      = "cn-beijing-MAZ2(f,g)"
}

resource "alicloud_api_gateway_group" "legacy" {
  group_name  = "legacy-group"
  instance_id = "legacy"
}
