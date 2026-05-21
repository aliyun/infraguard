resource "alicloud_api_gateway_api" "business_token" {
  auth_type = "APPOPENID"

  open_id_connect_config {
    open_id_api_type = "BUSINESS"
  }
}
