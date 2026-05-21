resource "alicloud_privatelink_vpc_endpoint_service" "configured" {
  service_description   = "My endpoint service"
  service_resource_type = "slb"
  auto_accept_connection = true
}
