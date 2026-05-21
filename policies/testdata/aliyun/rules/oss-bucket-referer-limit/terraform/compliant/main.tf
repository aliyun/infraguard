resource "alicloud_oss_bucket" "referer_protected" {
  bucket = "my-referer-bucket"
  acl    = "private"

  referer_config {
    allow_empty = false
    referers    = ["https://example.com", "https://*.example.com"]
  }
}
