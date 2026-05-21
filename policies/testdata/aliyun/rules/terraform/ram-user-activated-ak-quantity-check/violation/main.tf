resource "alicloud_ram_access_key" "key1" {
  user_name   = "user1"
  status      = "Active"
  secret_file = "/tmp/ak-secret1.txt"
}

resource "alicloud_ram_access_key" "key2" {
  user_name   = "user1"
  status      = "Active"
  secret_file = "/tmp/ak-secret2.txt"
}
