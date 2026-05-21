resource "alicloud_oss_bucket" "org_only" {
  bucket = "my-org-bucket"
  acl    = "private"

  policy = <<POLICY
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["oss:GetObject"],
      "Principal": ["1234567890"],
      "Resource": ["acs:oss:*:*:my-org-bucket/*"]
    }
  ]
}
POLICY
}
