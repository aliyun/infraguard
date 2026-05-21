resource "alicloud_ram_policy" "attached_policy" {
  policy_name     = "my-policy"
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

resource "alicloud_ram_role_policy_attachment" "attach" {
  policy_name = alicloud_ram_policy.attached_policy.policy_name
  policy_type = "Custom"
  role_name   = "my-role"
}
