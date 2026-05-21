resource "alicloud_oss_bucket" "tls_bucket" {
  bucket = "my-tls-bucket"
  acl    = "private"

  policy = <<POLICY
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["oss:*"],
      "Principal": ["*"],
      "Resource": ["acs:oss:*:*:my-tls-bucket/*"],
      "Condition": {
        "NumericLessThan": {
          "acs:TLSVersion": "1.2"
        }
      }
    }
  ]
}
POLICY
}
