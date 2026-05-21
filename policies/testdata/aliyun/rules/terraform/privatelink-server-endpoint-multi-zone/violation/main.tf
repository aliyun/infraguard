resource "alicloud_privatelink_vpc_endpoint_service" "unconfigured" {
  service_description    = "My endpoint service"
  auto_accept_connection = true
}
