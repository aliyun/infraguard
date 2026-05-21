resource "alicloud_ram_policy" "overly_permissive" {
  policy_name     = "admin-policy"
  policy_document = <<EOF
{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}],"Version":"1"}
EOF
}
