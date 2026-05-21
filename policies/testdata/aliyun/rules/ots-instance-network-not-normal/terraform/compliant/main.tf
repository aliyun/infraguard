resource "alicloud_ots_instance" "vpc_access" {
  name          = "tf-test-ots"
  instance_type = "Capacity"
  accessed_by   = "Vpc"
  tags = {
    Environment = "production"
  }
}
