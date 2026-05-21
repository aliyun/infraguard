resource "alicloud_ram_policy" "admin_access" {
  policy_name     = "admin-access-policy"
  policy_document = <<EOF
{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}],"Version":"1"}
EOF
}
