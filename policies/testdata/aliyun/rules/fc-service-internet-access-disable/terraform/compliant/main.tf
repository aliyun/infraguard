resource "alicloud_fc_service" "compliant" {
  name            = "test-service"
  internet_access = false
}
