resource "alicloud_ram_user" "user" {
  name         = "api-user"
  display_name = "API User"
}

resource "alicloud_ram_access_key" "ak" {
  user_name   = alicloud_ram_user.user.name
  status      = "Active"
  secret_file = "/tmp/ak.txt"
}
