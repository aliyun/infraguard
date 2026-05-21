resource "alicloud_fc_service" "compliant" {
  name = "test-service"
  role = "acs:ram::123456:role/fc-role"
}
