resource "alicloud_ram_role" "unrestricted" {
  name     = "unrestricted-role"
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
  description = "A role without max_session_duration set"
}
