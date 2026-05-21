resource "alicloud_ram_role" "role" {
  name     = "test-role"
  document = <<EOF
{
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "RAM": ["acs:ram::123456789:root"]
      }
    }
  ],
  "Version": "1"
}
EOF
}

resource "alicloud_ram_role_policy_attachment" "attach" {
  policy_name = "AliyunECSFullAccess"
  policy_type = "System"
  role_name   = alicloud_ram_role.role.name
}
