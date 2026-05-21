resource "alicloud_ots_instance" "public_access" {
  name          = "tf-test-ots"
  instance_type = "Capacity"
  accessed_by   = "Any"
  tags = {
    Environment = "production"
  }
}
