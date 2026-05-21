resource "alicloud_ram_role" "no_policy" {
  name        = "orphan-role"
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
  description = "A role without any policy attached"
}
