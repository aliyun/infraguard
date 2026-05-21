resource "alicloud_pai_service" "ha_service" {
  service_name = "my-pai-service"
  replicas     = 3
}
