resource "alicloud_ram_role" "limited" {
  name     = "limited-role"
  document = <<EOF
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
}

resource "alicloud_ram_role_policy_attachment" "readonly" {
  role_name   = alicloud_ram_role.limited.name
  policy_name = "AliyunOSSReadOnlyAccess"
  policy_type = "System"
}
