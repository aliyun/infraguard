resource "alicloud_ram_policy" "admin_access" {
  policy_name     = "admin-policy"
  policy_document = "{\"Version\":\"1\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
}
