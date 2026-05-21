resource "alicloud_pai_service" "single_zone" {
  service_name = "my-pai-service"
  replicas     = 1
}
