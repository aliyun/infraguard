resource "alicloud_fc_service" "compliant" {
  name = "test-service"

  vpc_config {
    vpc_id      = "vpc-123456"
    vswitch_ids = ["vsw-123456"]
  }
}
