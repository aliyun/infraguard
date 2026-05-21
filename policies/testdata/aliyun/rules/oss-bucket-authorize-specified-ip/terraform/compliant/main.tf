resource "alicloud_oss_bucket" "ip_restricted" {
  bucket = "my-ip-restricted-bucket"
  acl    = "private"

  policy = <<POLICY
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["oss:GetObject"],
      "Principal": ["1234567890"],
      "Resource": ["acs:oss:*:*:my-ip-restricted-bucket/*"],
      "Condition": {
        "IpAddress": {
          "acs:SourceIp": ["192.168.1.0/24"]
        }
      }
    }
  ]
}
POLICY
}
