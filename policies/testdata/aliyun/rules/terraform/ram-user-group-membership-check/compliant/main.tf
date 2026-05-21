resource "alicloud_ram_user" "user" {
  name         = "test-user"
  display_name = "Test User"
}

resource "alicloud_ram_group" "dev" {
  name = "dev-group"
}

resource "alicloud_ram_group_membership" "membership" {
  group_name = alicloud_ram_group.dev.name
  user_names = [alicloud_ram_user.user.name]
}
