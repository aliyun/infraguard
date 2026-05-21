resource "alicloud_api_gateway_group" "logged" {
  group_name = "logged-group"

  tags = {
    LogEnabled = "true"
  }
}
