resource "alicloud_api_gateway_group" "traced" {
  group_name = "traced-group"

  tags = {
    TracingEnabled = "true"
  }
}
