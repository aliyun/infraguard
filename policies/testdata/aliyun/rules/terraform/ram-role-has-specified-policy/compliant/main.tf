resource "alicloud_ram_role" "with_policy" {
  name        = "my-role"
  document    = <<EOF
{
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {"Service": ["ecs.aliyuncs.com"]}
    }
  ],
  "Version": "1"
}
EOF
  description = "A role with policy attached"
}

resource "alicloud_ram_role_policy_attachment" "attach" {
  policy_name = "ReadOnlyAccess"
  policy_type = "System"
  role_name   = alicloud_ram_role.with_policy.name
}
