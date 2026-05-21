resource "alicloud_api_gateway_api" "insecure" {
  visibility = "PUBLIC"

  request_config {
    request_protocol = "HTTP"
  }
}
