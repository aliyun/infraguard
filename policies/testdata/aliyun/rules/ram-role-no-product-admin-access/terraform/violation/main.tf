resource "alicloud_ram_role" "admin" {
  name     = "admin-role"
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

resource "alicloud_ram_role_policy_attachment" "admin_policy" {
  role_name   = alicloud_ram_role.admin.name
  policy_name = "AdministratorAccess"
  policy_type = "System"
}
