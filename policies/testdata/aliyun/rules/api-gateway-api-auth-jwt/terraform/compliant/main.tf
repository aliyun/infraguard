resource "alicloud_api_gateway_api" "jwt" {
  auth_type = "APPOPENID"

  open_id_connect_config {
    open_id_api_type = "IDTOKEN"
  }
}
