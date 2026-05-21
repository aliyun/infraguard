resource "alicloud_ram_policy" "restricted" {
  policy_name     = "restricted-policy"
  policy_document = <<EOF
{"Statement":[{"Effect":"Allow","Action":["ecs:Describe*"],"Resource":["acs:ecs:*:*:instance/*"]}],"Version":"1"}
EOF
}
