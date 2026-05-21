resource "alicloud_api_gateway_api" "secure" {
  visibility = "PUBLIC"

  request_config {
    request_protocol = "HTTPS"
  }
}
