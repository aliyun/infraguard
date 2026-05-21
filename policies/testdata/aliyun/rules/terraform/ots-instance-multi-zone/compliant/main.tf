resource "alicloud_ots_instance" "zone_redundant" {
  name          = "tf-test-ots"
  instance_type = "Capacity"
  accessed_by   = "ConsoleOrVpc"
  tags = {
    Environment = "production"
  }
}
