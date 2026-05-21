resource "alicloud_ram_policy" "unattached_policy" {
  policy_name     = "unused-policy"
  policy_document = <<EOF
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ecs:Describe*"],
      "Resource": ["*"]
    }
  ],
  "Version": "1"
}
EOF
}
