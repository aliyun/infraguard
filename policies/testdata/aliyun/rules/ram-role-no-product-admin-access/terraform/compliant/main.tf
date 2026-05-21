resource "alicloud_ram_role" "limited" {
  name                 = "limited-role"
  max_session_duration = 3600
  document             = <<EOF
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
  description = "A role with limited session duration"
}
