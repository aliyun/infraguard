resource "alicloud_oss_bucket" "replicated_bucket" {
  bucket = "my-replicated-bucket"
  acl    = "private"
}

resource "alicloud_oss_bucket_replication" "replication" {
  bucket = "my-replicated-bucket"

  destination {
    bucket   = "my-destination-bucket"
    location = "oss-cn-shanghai"
  }
}
