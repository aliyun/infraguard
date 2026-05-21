resource "alicloud_oss_bucket" "private_bucket" {
  bucket = "my-private-bucket"
  acl    = "private"
}
