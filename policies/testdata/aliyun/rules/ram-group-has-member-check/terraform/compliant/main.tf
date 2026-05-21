resource "alicloud_ram_group" "developers" {
  name = "developers"
}

resource "alicloud_ram_group_membership" "developers_members" {
  group_name = alicloud_ram_group.developers.name
  user_names = ["user1", "user2"]
}
