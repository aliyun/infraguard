resource "alicloud_oss_bucket" "anonymous_allowed" {
  bucket = "my-insecure-bucket"
  acl    = "private"

  policy = <<POLICY
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["oss:GetObject"],
      "Principal": ["*"],
      "Resource": ["acs:oss:*:*:my-insecure-bucket/*"]
    }
  ]
}
POLICY
}
