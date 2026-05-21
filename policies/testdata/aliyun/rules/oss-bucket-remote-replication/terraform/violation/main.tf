resource "alicloud_oss_bucket" "no_replication" {
  bucket = "my-bucket-no-replication"
  acl    = "private"
}
