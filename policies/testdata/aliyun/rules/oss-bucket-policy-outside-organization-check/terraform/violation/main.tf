resource "alicloud_oss_bucket" "outside_org" {
  bucket = "my-outside-org-bucket"
  acl    = "private"

  policy = <<POLICY
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["oss:GetObject"],
      "Principal": ["*"],
      "Resource": ["acs:oss:*:*:my-outside-org-bucket/*"]
    }
  ]
}
POLICY
}
