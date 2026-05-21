resource "alicloud_oss_bucket" "no_ip_restriction" {
  bucket = "my-bucket-no-ip"
  acl    = "private"
}
