resource "alicloud_oss_bucket" "lrs_bucket" {
  bucket          = "my-lrs-bucket"
  acl             = "private"
  redundancy_type = "LRS"
}
