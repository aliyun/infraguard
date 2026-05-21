resource "alicloud_ots_instance" "not_zone_redundant" {
  name          = "tf-test-ots"
  instance_type = "Capacity"
  accessed_by   = "Vpc"
  tags = {
    Environment = "production"
  }
}
