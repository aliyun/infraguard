resource "alicloud_ram_user" "user" {
  name         = "console-user"
  display_name = "Console User"
}

resource "alicloud_ram_login_profile" "profile" {
  user_name         = alicloud_ram_user.user.name
  password          = "Example@12345"
  mfa_bind_required = false
}
