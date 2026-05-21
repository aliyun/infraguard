resource "alicloud_ram_user" "user" {
  name         = "test-user"
  display_name = "Test User"
}

resource "alicloud_ram_user_policy_attachment" "attach" {
  policy_name = "AdministratorAccess"
  policy_type = "System"
  user_name   = alicloud_ram_user.user.name
}
