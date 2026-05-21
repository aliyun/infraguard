resource "alicloud_oss_bucket" "zrs_bucket" {
  bucket          = "my-zrs-bucket"
  acl             = "private"
  redundancy_type = "ZRS"
}
