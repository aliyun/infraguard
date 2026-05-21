resource "alicloud_oss_bucket" "https_only" {
  bucket = "my-https-only-bucket"
  acl    = "private"

  policy = <<POLICY
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["oss:*"],
      "Principal": ["*"],
      "Resource": ["acs:oss:*:*:my-https-only-bucket/*"],
      "Condition": {
        "Bool": {
          "acs:SecureTransport": "false"
        }
      }
    }
  ]
}
POLICY
}
