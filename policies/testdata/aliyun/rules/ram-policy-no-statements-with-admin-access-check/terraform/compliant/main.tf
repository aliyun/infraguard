resource "alicloud_ram_policy" "least_privilege" {
  policy_name     = "least-privilege-policy"
  policy_document = <<EOF
{"Statement":[{"Effect":"Allow","Action":["ecs:Describe*","ecs:List*"],"Resource":["acs:ecs:*:*:instance/*"]}],"Version":"1"}
EOF
}
