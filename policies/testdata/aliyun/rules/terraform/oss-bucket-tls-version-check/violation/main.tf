resource "alicloud_oss_bucket" "no_tls_policy" {
  bucket = "my-bucket-no-tls"
  acl    = "private"
}
