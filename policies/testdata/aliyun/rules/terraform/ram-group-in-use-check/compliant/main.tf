resource "alicloud_ram_group" "active_group" {
  name = "active-group"
}

resource "alicloud_ram_group_membership" "active_members" {
  group_name = alicloud_ram_group.active_group.name
  user_names = ["user1"]
}
