resource "alicloud_oss_bucket" "no_anonymous" {
  bucket = "my-secure-bucket"
  acl    = "private"

  policy = <<POLICY
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["oss:GetObject"],
      "Principal": ["1234567890"],
      "Resource": ["acs:oss:*:*:my-secure-bucket/*"]
    }
  ]
}
POLICY
}
